import { verifyKel, type KelSeal } from "./kel.js";
import { anchoredIssuance, readTel, type TelReading } from "./tel.js";
import { declaredSaid, recomputeSaid } from "./said.js";
import type {
  CheckStatus,
  OfflineVerificationResult,
  TrustBand,
  TrustCheckCounts,
  TrustReport,
  TrustReportStep,
  TrustReportSteps,
  TrustScore,
  TrustableVerifyPackage,
} from "./types.js";

export const SUPPORTED_SCHEMA_VERSION = 1;

/** Raised for a package this library cannot judge at all. */
export class UnsupportedPackageError extends Error {
  readonly code: string;
  constructor(message: string, code: string) {
    super(message);
    this.name = "UnsupportedPackageError";
    this.code = code;
  }
}

function step(
  status: CheckStatus,
  message: string,
  details: string,
  timestamp: string,
): TrustReportStep {
  return { status, passed: status === "passed", message, details, timestamp };
}

/**
 * The Platform's scoring, reproduced exactly — same weights, same banding, same
 * counts.
 *
 * Reproduced rather than simplified because the number is read by app UIs
 * beside the hosted one, and two scales that disagree about the same evidence
 * are worse than one scale nobody loves. Note what that means offline: witness
 * receipts and watcher status are optional checks this path cannot run, and the
 * band only reaches `high` when an optional check passes — so a package that
 * verifies completely still bands `medium` at 70. That is the honest reading,
 * not a penalty.
 */
const REQUIRED_WEIGHTS = {
  kelDiscovery: 15,
  cryptographicVerification: 20,
  telValidation: 20,
  revocationStatus: 15,
} as const;

const OPTIONAL_WEIGHTS = {
  witnessReceipts: 15,
  watcherStatus: 15,
} as const;

export function computeTrustScore(
  steps: TrustReportSteps | Partial<Record<string, TrustReportStep>>,
): TrustScore {
  const requiredKeys = Object.keys(REQUIRED_WEIGHTS) as (keyof typeof REQUIRED_WEIGHTS)[];
  const optionalKeys = Object.keys(OPTIONAL_WEIGHTS) as (keyof typeof OPTIONAL_WEIGHTS)[];

  const counts: TrustCheckCounts = {
    passed: 0,
    skipped: 0,
    degraded: 0,
    failed: 0,
    total: requiredKeys.length + optionalKeys.length,
    runnable: 0,
  };

  let rawScore = 0;
  let requiredFailed = false;
  let requiredDegraded = false;
  let anyOptionalPassed = false;

  const tally = (
    step: TrustReportStep | undefined,
    weight: number,
    isRequired: boolean,
  ): void => {
    // A missing step counts as degraded when it was required — evidence was
    // expected and none arrived — and as skipped when it was optional.
    const status: CheckStatus = step?.status ?? (isRequired ? "degraded" : "skipped");
    switch (status) {
      case "passed":
        counts.passed += 1;
        counts.runnable += 1;
        rawScore += weight;
        if (!isRequired) anyOptionalPassed = true;
        break;
      case "skipped":
        counts.skipped += 1;
        break;
      case "degraded":
        counts.degraded += 1;
        counts.runnable += 1;
        if (isRequired) requiredDegraded = true;
        break;
      case "failed":
        counts.failed += 1;
        counts.runnable += 1;
        if (isRequired) requiredFailed = true;
        break;
    }
  };

  const all = steps as Partial<Record<string, TrustReportStep>>;
  for (const key of requiredKeys) tally(all[key], REQUIRED_WEIGHTS[key], true);
  // Witness receipts and watcher status are checks the hosted path can run and
  // this one cannot, so they are never present here. They are still tallied, as
  // skipped, because that is what decides the band — and dropping them would
  // quietly promote every offline report a rung.
  for (const key of optionalKeys) tally(all[key], OPTIONAL_WEIGHTS[key], false);

  let band: TrustBand;
  let score: number;
  if (requiredFailed) {
    band = "failed";
    score = 0;
  } else if (requiredDegraded) {
    band = "limited";
    score = Math.min(rawScore, 60);
  } else if (anyOptionalPassed) {
    band = "high";
    score = rawScore;
  } else {
    band = "medium";
    score = Math.min(rawScore, 70);
  }

  const confidence =
    counts.runnable === 0
      ? 0
      : Math.round((counts.passed / counts.runnable) * 100) / 100;

  return { score, confidence, band, counts };
}

function checkStructure(
  pkg: TrustableVerifyPackage,
  timestamp: string,
): TrustReportStep {
  const missing: string[] = [];
  if (!pkg.acdc_said) missing.push("acdc_said");
  if (!pkg.issuer_aid) missing.push("issuer_aid");
  if (!pkg.cesr && !pkg.acdc) missing.push("cesr or acdc");
  if (missing.length > 0) {
    return step(
      "failed",
      "Package structure is incomplete",
      `Missing: ${missing.join(", ")}`,
      timestamp,
    );
  }

  // The package's own header has to agree with the credential it carries.
  // Every step below keys off `acdc_said` and `issuer_aid` — the key log is
  // walked for that issuer, the anchor is matched for that credential — so a
  // package free to name a credential or an issuer its ACDC does not would have
  // those checks vouching for something other than what a reader is looking at.
  const acdc = pkg.acdc;
  if (acdc && typeof acdc["d"] === "string" && acdc["d"] !== pkg.acdc_said) {
    return step(
      "failed",
      "Package is internally inconsistent",
      `The ACDC's own identifier (${String(acdc["d"])}) is not the acdc_said the package declares (${pkg.acdc_said})`,
      timestamp,
    );
  }
  if (acdc && typeof acdc["i"] === "string" && acdc["i"] !== pkg.issuer_aid) {
    return step(
      "failed",
      "Package is internally inconsistent",
      `The ACDC's issuer (${String(acdc["i"])}) is not the issuer_aid the package declares (${pkg.issuer_aid})`,
      timestamp,
    );
  }

  return step(
    "passed",
    "Package structure is complete",
    "Every field an offline verdict depends on is present, and the credential agrees with the header that describes it",
    timestamp,
  );
}

function checkSaidIntegrity(
  pkg: TrustableVerifyPackage,
  timestamp: string,
): TrustReportStep {
  if (!pkg.cesr) {
    return step(
      "degraded",
      "SAID integrity not checked",
      pkg.integrity?.reason ??
        "The package carries no CESR stream, so the SAID cannot be recomputed. The `acdc` field is a stored projection and a digest over a projection proves nothing.",
      timestamp,
    );
  }

  const recomputed = recomputeSaid(pkg.cesr);
  if (recomputed === null) {
    return step(
      "failed",
      "SAID integrity failed",
      "The packaged CESR carries no identifier field to recompute",
      timestamp,
    );
  }
  if (recomputed !== pkg.acdc_said) {
    return step(
      "failed",
      "SAID integrity failed",
      `The packaged bytes hash to ${recomputed}, not the ${pkg.acdc_said} this package is about`,
      timestamp,
    );
  }
  const embedded = declaredSaid(pkg.cesr);
  if (embedded !== pkg.acdc_said) {
    return step(
      "failed",
      "SAID integrity failed",
      `The packaged bytes describe credential ${String(embedded)}, not ${pkg.acdc_said}`,
      timestamp,
    );
  }
  return step(
    "passed",
    "SAID integrity verified",
    `Recomputed over the packaged CESR and matched ${pkg.acdc_said}`,
    timestamp,
  );
}

/**
 * Verify a Trustable from its portable package, with no network access.
 *
 * Nothing here reads a URL, a file or a clock beyond stamping the report. The
 * verdict is a function of the bytes handed in — which is the property that
 * makes the answer checkable by someone who does not trust whoever produced it.
 */
export function verifyPackage(
  pkg: TrustableVerifyPackage,
): OfflineVerificationResult {
  const timestamp = new Date().toISOString();

  if (pkg?.schema_version !== SUPPORTED_SCHEMA_VERSION) {
    throw new UnsupportedPackageError(
      `Unsupported package schema_version: ${String(pkg?.schema_version)}. This verifier understands version ${SUPPORTED_SCHEMA_VERSION}.`,
      "UNSUPPORTED_PACKAGE_VERSION",
    );
  }
  if (!pkg.acdc_said || !pkg.issuer_aid) {
    throw new UnsupportedPackageError(
      "Package is missing acdc_said or issuer_aid — there is nothing to verify against.",
      "INCOMPLETE_PACKAGE",
    );
  }

  const structureValidation = checkStructure(pkg, timestamp);
  const saidIntegrity = checkSaidIntegrity(pkg, timestamp);

  // The KEL first: it is the only signed thing in the package, so every answer
  // below is conditional on it.
  const kelResult = pkg.kel
    ? verifyKel(pkg.kel, pkg.issuer_aid)
    : { failure: { reason: "The package carries no KEL" } };
  const kel = "kel" in kelResult ? kelResult.kel : null;
  const anchors: KelSeal[] = kel?.anchors ?? [];

  const kelDiscovery = kel
    ? step(
        "passed",
        "Issuer key state verified",
        `${kel.eventCount} key events, each hashing to its own identifier, chained, and signed by the keys in force`,
        timestamp,
      )
    : step(
        "failed",
        "Issuer key state not established",
        "failure" in kelResult
          ? kelResult.failure.reason
          : "The package carries no KEL",
        timestamp,
      );

  // Both logs are read against the same anchors: the registry's inception is
  // anchored in the same KEL as the issuance it gives meaning to.
  const credentialTel: TelReading = readTel(pkg.tel, anchors);
  const registryTel: TelReading = readTel(pkg.registry_tel, anchors);
  const issuance = anchoredIssuance(credentialTel, pkg.acdc_said);

  const telValidation =
    credentialTel.events.length === 0
      ? step(
          "failed",
          "No TEL available",
          "The package carries no registry history for this credential",
          timestamp,
        )
      : credentialTel.anchoredCount === 0
        ? step(
            "degraded",
            "TEL present but unanchored",
            "No registry event could be matched to a seal in the verified KEL — the history is readable but nothing binds it to the issuer",
            timestamp,
          )
        : step(
            "passed",
            "TEL anchored to the issuer's KEL",
            `${credentialTel.anchoredCount} of ${credentialTel.events.length} registry events matched a seal in the verified KEL${
              registryTel.anchoredCount > 0
                ? ", and the registry's own inception is anchored too"
                : ""
            }`,
            timestamp,
          );

  // Authorship. Recomputing a SAID shows a credential hashes to itself, which
  // anyone can arrange for a credential they minted. What proves the ISSUER
  // authored it is the chain: this credential's issuance event, hashed from its
  // own bytes, named by a seal inside a key event this issuer signed.
  const cryptographicVerification = issuance
    ? step(
        "passed",
        "Issuer authorship verified",
        `The issuance of ${pkg.acdc_said} is sealed into ${pkg.issuer_aid}'s signed key event log`,
        timestamp,
      )
    : step(
        "failed",
        "Issuer authorship not established",
        kel
          ? credentialTel.events.length === 0
            ? "The package carries no registry history, so there is no issuance event to anchor"
            : "No issuance of this credential is sealed into the issuer's key event log"
          : "The issuer's key state could not be established, so nothing can be anchored to it",
        timestamp,
      );

  const schemaCompliance = step(
    "degraded",
    "Schema not checked",
    pkg.schema
      ? "A schema document travelled with the package, but compliance is not evaluated on this path"
      : "No schema document in the package; export with include_schema=true to carry one",
    timestamp,
  );

  const status = credentialTel.status;
  const revocationStatus =
    status === "revoked"
      ? step(
          "failed",
          "Credential is revoked",
          `The latest anchored registry event is a revocation, as of ${pkg.packaged_at ?? "an unstated time"}`,
          timestamp,
        )
      : status === "issued"
        ? step(
            "passed",
            "Credential is not revoked",
            `Checked against the anchored registry history, as of ${pkg.packaged_at ?? "an unstated time"}`,
            timestamp,
          )
        : step(
            "degraded",
            "Revocation status unknown",
            "No anchored registry event states a status, so this package cannot say whether the credential stands",
            timestamp,
          );

  const steps: TrustReportSteps = {
    structureValidation,
    saidIntegrity,
    schemaCompliance,
    cryptographicVerification,
    kelDiscovery,
    telValidation,
    revocationStatus,
  };

  const trustScore = computeTrustScore(steps);
  const failed = Object.values(steps).some((s) => s.status === "failed");

  // Authenticity has to be PROVEN, not merely un-disproven — both the bytes and
  // the authorship, or the answer is integrity only.
  const authenticity =
    saidIntegrity.status === "passed" &&
    cryptographicVerification.status === "passed";

  // A suspension is not a registry event: the credential still reads as issued,
  // and a package that ignored it would be the way to route around one.
  const suspended = pkg.trustable_status?.current_state === "suspended";
  const isValid = status === "issued" && !failed && !suspended && authenticity;

  const trustReport: TrustReport = {
    steps,
    status:
      status === "revoked"
        ? "revoked"
        : suspended
          ? "suspended"
          : isValid
            ? "verified"
            : "invalid",
    isValid,
    trustScore,
    verifiedAt: timestamp,
    credentialSaid: pkg.acdc_said,
    issuerAid: pkg.issuer_aid,
  };

  return {
    isValid,
    status: trustReport.status,
    credentialSaid: pkg.acdc_said,
    issuerAid: pkg.issuer_aid,
    verifiedAt: timestamp,
    trustScore,
    trustReport,
    authenticity: {
      established: authenticity,
      ...(authenticity
        ? {}
        : {
            reason:
              cryptographicVerification.status !== "passed"
                ? cryptographicVerification.details
                : "SAID integrity could not be established for this package.",
          }),
    },
    verification_mode: "offline",
    // An undated package gets no `as_of` rather than a flattering one.
    as_of: pkg.packaged_at ?? null,
  package_schema_version: SUPPORTED_SCHEMA_VERSION,
  };
}
