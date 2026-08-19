import { ed25519 } from "@noble/curves/ed25519";
import { parseCesrStream, type ParsedEvent } from "./cesr.js";
import { decodeVerkey } from "./qb64.js";
import { recomputeEventSaid } from "./said.js";

/**
 * Verifies a key event log and reports what it establishes.
 *
 * The KEL is the only thing in a package that carries signatures, so it is the
 * root of every other answer. Walking it means three checks at once: that each
 * event hashes to the identifier it claims, that it names the previous event's
 * digest, and that it is signed by the keys that were in force when it was
 * written — where "in force" is decided by the establishment events already
 * walked, never by the event proving itself.
 */

export interface KelSeal {
  /** The identifier the seal points at — a registry or a credential. */
  i?: string;
  /** Sequence number of the sealed event, as written. */
  s?: string;
  /** The sealed event's SAID. This is the field an anchor is matched on. */
  d?: string;
}

export interface VerifiedKel {
  issuerAid: string;
  eventCount: number;
  /** Seals from every event whose signatures verified. */
  anchors: KelSeal[];
  /** Public keys in force after the last establishment event. */
  currentKeys: string[];
}

export interface KelFailure {
  reason: string;
  atSequence?: number;
}

const ESTABLISHMENT = new Set(["icp", "rot", "dip", "drt"]);

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function signingThreshold(event: Record<string, unknown>): number {
  const kt = event["kt"];
  // Only the simple forms are honoured. A weighted or multi-clause threshold
  // describes a policy this verifier cannot evaluate, and treating one as "1"
  // would accept a single signature where the controller demanded several.
  if (typeof kt === "string" && /^[0-9a-f]+$/i.test(kt)) {
    return parseInt(kt, 16);
  }
  if (typeof kt === "number") return kt;
  return Number.NaN;
}

function verifySignatures(
  event: ParsedEvent,
  keys: string[],
  threshold: number,
): boolean {
  if (!Number.isFinite(threshold) || threshold < 1) return false;

  const message = new TextEncoder().encode(event.raw);
  const satisfied = new Set<number>();

  for (const { index, signature } of event.signatures) {
    const key = keys[index];
    if (key === undefined || satisfied.has(index)) continue;
    let verkey: Uint8Array;
    try {
      verkey = decodeVerkey(key);
    } catch {
      continue;
    }
    if (ed25519.verify(signature, message, verkey)) satisfied.add(index);
  }

  return satisfied.size >= threshold;
}

/**
 * Walk a signed KEL stream for one identifier.
 *
 * Returns the failure rather than throwing: an unverifiable KEL is an answer
 * about the credential, not an error in the verifier.
 */
export function verifyKel(
  stream: string,
  issuerAid: string,
): { kel: VerifiedKel } | { failure: KelFailure } {
  const events = parseCesrStream(stream);
  if (events.length === 0) {
    return { failure: { reason: "The packaged KEL contains no readable events" } };
  }

  let keys: string[] = [];
  let threshold = Number.NaN;
  let previousSaid: string | null = null;
  let expectedSequence = 0;
  const anchors: KelSeal[] = [];

  for (const event of events) {
    const { sad, raw } = event;
    const type = typeof sad["t"] === "string" ? (sad["t"] as string) : "";
    const prefix = typeof sad["i"] === "string" ? (sad["i"] as string) : "";
    const said = typeof sad["d"] === "string" ? (sad["d"] as string) : "";
    const sequence = parseInt(
      typeof sad["s"] === "string" ? (sad["s"] as string) : "",
      16,
    );

    if (prefix !== issuerAid) {
      return {
        failure: {
          reason: `The packaged KEL is for ${prefix || "an unnamed identifier"}, not the issuer ${issuerAid} this credential names`,
          atSequence: sequence,
        },
      };
    }

    if (sequence !== expectedSequence) {
      return {
        failure: {
          reason: `The KEL skips from ${expectedSequence - 1} to ${sequence} — an incomplete log cannot establish key state`,
          atSequence: sequence,
        },
      };
    }

    if (recomputeEventSaid(raw) !== said) {
      return {
        failure: {
          reason: `Event ${sequence} does not hash to the identifier it carries`,
          atSequence: sequence,
        },
      };
    }

    if (previousSaid !== null && sad["p"] !== previousSaid) {
      return {
        failure: {
          reason: `Event ${sequence} does not name event ${sequence - 1} as its prior — the chain is broken`,
          atSequence: sequence,
        },
      };
    }

    // Establishment events carry the keys that sign them; everything else is
    // signed by whatever the last establishment event put in force. Reading an
    // interaction event's own `k` would let a forged event nominate the keys
    // that make it valid.
    if (ESTABLISHMENT.has(type)) {
      keys = asStringArray(sad["k"]);
      threshold = signingThreshold(sad);
    }

    if (keys.length === 0) {
      return {
        failure: {
          reason: `No key state was established before event ${sequence}`,
          atSequence: sequence,
        },
      };
    }

    if (!verifySignatures(event, keys, threshold)) {
      return {
        failure: {
          reason: `Event ${sequence} is not signed by the keys in force at that point`,
          atSequence: sequence,
        },
      };
    }

    const seals = sad["a"];
    if (Array.isArray(seals)) {
      for (const seal of seals) {
        if (seal && typeof seal === "object") anchors.push(seal as KelSeal);
      }
    }

    previousSaid = said;
    expectedSequence += 1;
  }

  return {
    kel: {
      issuerAid,
      eventCount: events.length,
      anchors,
      currentKeys: keys,
    },
  };
}
