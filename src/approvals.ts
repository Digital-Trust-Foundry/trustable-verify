import { sadFromCesr } from "./acdc.js";
import { verifyKel } from "./kel.js";
import { anchoredIssuance, readTel } from "./tel.js";
import { declaredSaid, recomputeSaid } from "./said.js";

/**
 * Proving the approvals a Trustable required actually happened.
 *
 * Every custodial approval is a credential in its own right: minted by the
 * signer's own identifier, chained back to the credential it approves by an
 * `e.genesis.n` edge, and its issuance sealed into the signer's key event log
 * exactly as the genesis issuance is sealed into the issuer's. So an approval
 * is proven by the same walk the genesis credential gets, run against the
 * signer's log rather than the issuer's — and nothing here takes the package's
 * word for who signed, which credential was approved, or whether the approval
 * still stands.
 */

/** One approval credential and its evidence, as the export writes it. */
export interface PackagedApproval {
  acdc_said?: string;
  issuer_aid?: string;
  registry_id?: string;
  /** The approval credential's own CESR stream. */
  cesr?: string;
  /**
   * The approving signer's signed KEL. Omitted when the signer IS the genesis
   * issuer, whose log already travels at the top level of the package.
   */
  kel?: string;
  tel?: unknown;
  registry_tel?: unknown;
  [key: string]: unknown;
}

export interface ProvenApproval {
  acdcSaid: string;
  /** The signer — the identifier that issued this approval credential. */
  issuerAid: string;
  /** The collection round this approval was cast in, when it names one. */
  roundId: string | null;
}

export interface RejectedApproval {
  /** The credential as best it can be named — its own SAID, or the claim. */
  acdcSaid: string;
  reason: string;
}

export interface ApprovalReading {
  proven: ProvenApproval[];
  rejected: RejectedApproval[];
}

function reject(
  rejected: RejectedApproval[],
  approval: PackagedApproval,
  reason: string,
): void {
  rejected.push({
    acdcSaid:
      typeof approval.acdc_said === "string" ? approval.acdc_said : "unnamed",
    reason,
  });
}

/**
 * Read every packaged approval against the credential it claims to approve.
 *
 * `genesisKel` is the issuer's log, already carried for the genesis credential;
 * an approval whose signer is that same identifier reuses it rather than
 * shipping a second copy. Everyone else brings their own.
 */
export function readApprovals(
  approvals: unknown,
  credentialSaid: string,
  genesisIssuerAid: string,
  genesisKel: string | undefined,
): ApprovalReading {
  const proven: ProvenApproval[] = [];
  const rejected: RejectedApproval[] = [];
  if (!Array.isArray(approvals)) return { proven, rejected };

  // One signer can appear more than once across rounds, and walking a KEL means
  // an ed25519 check per event. Verified once per distinct log.
  const walked = new Map<string, ReturnType<typeof verifyKel>>();

  for (const entry of approvals as PackagedApproval[]) {
    if (!entry || typeof entry !== "object") continue;

    const cesr = typeof entry.cesr === "string" ? entry.cesr : null;
    if (cesr === null) {
      reject(
        rejected,
        entry,
        "The package carries no serialisation for this approval, so there is nothing to recompute an identity from",
      );
      continue;
    }

    // Identity first, out of the bytes. Everything below is matched on this
    // value, so taking the package's word for it would let one approval claim
    // another's anchor.
    const recomputed = recomputeSaid(cesr);
    if (recomputed === null || recomputed !== declaredSaid(cesr)) {
      reject(
        rejected,
        entry,
        "The approval's bytes do not hash to the identifier they carry",
      );
      continue;
    }
    if (
      typeof entry.acdc_said === "string" &&
      entry.acdc_said !== "" &&
      entry.acdc_said !== recomputed
    ) {
      reject(
        rejected,
        entry,
        `The package names approval ${entry.acdc_said}, but the bytes beside it are ${recomputed}`,
      );
      continue;
    }

    const sad = sadFromCesr(cesr);
    if (!sad) {
      reject(rejected, entry, "The approval's serialisation could not be read");
      continue;
    }

    // The edge is what makes this an approval OF this credential rather than a
    // valid credential about something else entirely.
    const edges = sad["e"];
    const genesis =
      edges && typeof edges === "object"
        ? (edges as Record<string, unknown>)["genesis"]
        : null;
    const parent =
      genesis && typeof genesis === "object"
        ? (genesis as Record<string, unknown>)["n"]
        : null;
    if (parent !== credentialSaid) {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        typeof parent === "string"
          ? `This approval chains to ${parent}, not to the credential being verified`
          : "This approval carries no edge back to the credential being verified",
      );
      continue;
    }

    const issuer = typeof sad["i"] === "string" ? (sad["i"] as string) : "";
    if (issuer === "") {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        "The approval names no issuer",
      );
      continue;
    }
    if (
      typeof entry.issuer_aid === "string" &&
      entry.issuer_aid !== "" &&
      entry.issuer_aid !== issuer
    ) {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        `The package attributes this approval to ${entry.issuer_aid}, but it was issued by ${issuer}`,
      );
      continue;
    }

    // The signer named in the body has to be the identifier that actually
    // issued it. A credential minted by one signer while naming another would
    // otherwise count toward the second one's place in the set.
    const attributes = sad["a"];
    const body =
      attributes && typeof attributes === "object"
        ? (attributes as Record<string, unknown>)
        : {};
    const signerAid = body["signer_aid"];
    if (typeof signerAid === "string" && signerAid !== issuer) {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        `This approval says it was cast by ${signerAid} but was issued by ${issuer}`,
      );
      continue;
    }

    const kel =
      typeof entry.kel === "string"
        ? entry.kel
        : issuer === genesisIssuerAid
          ? genesisKel
          : undefined;
    if (kel === undefined) {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        `The package carries no key event log for ${issuer}, so nothing this signer wrote can be checked`,
      );
      continue;
    }

    const cacheKey = `${issuer}\n${kel}`;
    let walkedKel = walked.get(cacheKey);
    if (walkedKel === undefined) {
      walkedKel = verifyKel(kel, issuer);
      walked.set(cacheKey, walkedKel);
    }
    if (!("kel" in walkedKel)) {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        `The key event log for ${issuer} does not verify: ${walkedKel.failure.reason}`,
      );
      continue;
    }

    // Same walk the genesis credential gets: the issuance event hashed from its
    // own bytes, and named by a seal inside a key event this signer signed.
    const tel = readTel(entry.tel, walkedKel.kel.anchors);
    if (anchoredIssuance(tel, recomputed) === null) {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        tel.events.length === 0
          ? "The package carries no registry history for this approval"
          : `No issuance of this approval is sealed into ${issuer}'s key event log`,
      );
      continue;
    }

    // A signer can take an approval back, and the registry says so the same way
    // it says a credential was revoked. Counting one would be counting a
    // withdrawn vote.
    if (tel.status === "revoked") {
      reject(
        rejected,
        { ...entry, acdc_said: recomputed },
        "This approval was revoked by the signer who cast it",
      );
      continue;
    }

    proven.push({
      acdcSaid: recomputed,
      issuerAid: issuer,
      roundId: typeof body["round_id"] === "string" ? body["round_id"] : null,
    });
  }

  return { proven, rejected };
}

/**
 * Whether the proven approvals satisfy the policy the credential itself names.
 *
 * Counted per ROUND, not across the package as a whole: a threshold is a
 * statement about one collection, and adding up votes cast in different rounds
 * would let two separate one-signer approvals stand in for a round that needed
 * two. Within a round, signers are counted once each, and only signers the
 * policy actually names when it names a set.
 */
export function satisfiedRound(
  proven: ProvenApproval[],
  threshold: number,
  candidates: string[],
): { met: boolean; best: number; roundId: string | null } {
  const eligible =
    candidates.length > 0
      ? proven.filter((approval) => candidates.includes(approval.issuerAid))
      : proven;

  const rounds = new Map<string, Set<string>>();
  for (const approval of eligible) {
    const key = approval.roundId ?? "";
    const signers = rounds.get(key) ?? new Set<string>();
    signers.add(approval.issuerAid);
    rounds.set(key, signers);
  }

  let best = 0;
  let bestRound: string | null = null;
  for (const [roundId, signers] of rounds) {
    if (signers.size > best) {
      best = signers.size;
      bestRound = roundId === "" ? null : roundId;
    }
  }

  return { met: best >= threshold, best, roundId: bestRound };
}
