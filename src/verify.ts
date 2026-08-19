import { verifyKel, type KelSeal } from "./kel.js";
import { anchoredIssuance, readTel, type TelReading } from "./tel.js";
import { declaredSaid, recomputeSaid } from "./said.js";
import type {
  CheckStatus,
  OfflineVerificationResult,
  TrustReport,
  TrustReportStep,
  TrustReportSteps,
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
 * The same scoring the hosted path applies, so one report cannot read better
 * than the other for the same evidence.
 */
function computeTrustScore(steps: TrustReportSteps): TrustReport["trustScore"] {
  const required = [
    steps.structureValidation,
    steps.saidIntegrity,
    steps.cryptographicVerification,
    steps.revocationStatus,
  ];
  if (required.some((s) => s.status === "failed")) return "failed";
  if (required.some((s) => s.status === "degraded")) return "limited";
  const optional = [steps.schemaCompliance, steps.kelDiscovery, steps.telValidation];
  return optional.some((s) => s.status === "passed") ? "high" : "medium";
}

function checkStructure(
  pkg: TrustableVerifyPackage,
  timestamp: string,
): TrustReportStep {
  const missing: string[] = [];
  if (!pkg.acdc_said) missing.push("acdc_said");
  if (!pkg.issuer_aid) missing.push("issuer_aid");
  if (!pkg.cesr && !pkg.acdc) missing.push("cesr or acdc");
  return missing.length === 0
    ? step(
        "passed",
        "Package structure is complete",
        "Every field an offline verdict depends on is present",
        timestamp,
      )
    : step(
        "failed",
        "Package structure is incomplete",
        `Missing: ${missing.join(", ")}`,
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
