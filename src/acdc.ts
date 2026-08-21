/**
 * Reading a credential out of the bytes it was issued as.
 *
 * Everything here works on the CESR stream and never on `pkg.acdc` or any other
 * projection beside it: the fields that decide a verdict — the identifier, the
 * issuer, the signature policy, the edge back to a parent — all sit inside the
 * envelope the SAID is computed over, so reading them from the stream is what
 * makes them uneditable.
 */
import { parseCesrStream } from "./cesr.js";

/**
 * The credential's own serialisation, parsed.
 *
 * Framed by `parseCesrStream`, which is the only thing in this package that
 * knows how a version string is written. It used to be framed here too, by a
 * second regex that read the 1.0 spelling only — so a credential issued at
 * 2.0 parsed as `null`, and every caller read that as "no credential" rather
 * than "could not be read". The approval an officer's device signs is 2.0,
 * which made `readApprovals` return nothing on the exact credentials it
 * exists to count, while a 1.0 genesis credential beside it read fine and
 * every other check on the page passed.
 *
 * One implementation, so a version this package learns to frame is a version
 * it can read everywhere. JSON only, still: matching the CBOR or MGPK
 * variants would slice bytes `JSON.parse` always rejects and dress the
 * failure up as a successful read.
 */
export function sadFromCesr(cesr: string): Record<string, unknown> | null {
  const [first] = parseCesrStream(cesr);
  if (!first) return null;

  // A credential, not whatever else arrives framed the same way. `sadFromCesr`
  // is asked for the thing a SAID and a policy are read out of, and handing
  // back the first event of a key event log because it happened to be framed
  // identically would be a confidently wrong answer.
  const version = first.sad["v"];
  return typeof version === "string" && version.startsWith("ACDC")
    ? first.sad
    : null;
}

/** One named candidate in a bound signature policy. */
export interface PolicyCandidate {
  actorAid: string;
}

/** The approval requirement a credential carries in its own envelope. */
export interface BoundPolicy {
  threshold: number;
  /** Candidate AIDs, when the policy names a set. Empty when it names none. */
  candidates: string[];
  /** Roles the policy demands of its signers. Not checkable from the bytes. */
  requiredRoles: string[];
  requiresRound: boolean;
}

/**
 * What the credential itself says about the approvals it required.
 *
 * Read out of the packaged CESR, never out of `pkg.acdc` or `pkg.signature_policy`
 * — those are projections a holder can edit. The policy is inside the envelope
 * the SAID is computed over, so a credential that names a threshold cannot be
 * made to stop naming it.
 */
export function boundPolicy(cesr: string | undefined): BoundPolicy | null {
  if (!cesr) return null;
  const sad = sadFromCesr(cesr);
  const attributes = sad?.["a"];
  if (!attributes || typeof attributes !== "object") return null;
  const policy = (attributes as Record<string, unknown>)["signature_policy"];
  if (!policy || typeof policy !== "object") return null;
  const fields = policy as Record<string, unknown>;
  const declared = fields["threshold"];
  const candidates = Array.isArray(fields["candidates"])
    ? (fields["candidates"] as unknown[])
        .map((entry) =>
          entry && typeof entry === "object"
            ? (entry as Record<string, unknown>)["actor_aid"]
            : null,
        )
        .filter((aid): aid is string => typeof aid === "string" && aid !== "")
    : [];
  const requiredRoles = Array.isArray(fields["required_roles"])
    ? (fields["required_roles"] as unknown[]).filter(
        (role): role is string => typeof role === "string" && role !== "",
      )
    : [];
  const named = candidates.length;
  // A threshold is a count of signatures, so anything that is not a whole
  // number of them is not a policy — it is a field somebody filled in wrong, or
  // filled in deliberately. Zero is the one that matters: with a named set it
  // would make the round required and satisfied at the same time, passing a
  // credential nobody approved. One approval is the floor.
  const counted =
    typeof declared === "number" && Number.isInteger(declared) && declared > 0
      ? declared
      : 1;
  // `kind: "all"` means every named candidate, so the real threshold is the
  // size of the set rather than the number written down.
  const threshold = fields["kind"] === "all" && named > 0 ? named : counted;

  // A named candidate set is the decisive part, not the count. "These signers
  // and no others" with a threshold of one is a 1-of-N approval: a specific
  // person still has to approve, and the credential is minted before anyone is
  // asked. Reading only the threshold would wave that through — which is
  // exactly the case a product about officer authority cannot get wrong.
  return {
    threshold,
    candidates,
    requiredRoles,
    requiresRound: named > 0 || threshold > 1,
  };
}
