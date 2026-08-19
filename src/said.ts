import { blake3 } from "@noble/hashes/blake3";
import { encodeDigest } from "./qb64.js";

/**
 * A self-addressing identifier is a digest of the very field that carries it,
 * which is only well defined because the field is first replaced by a dummy of
 * its own length. Recomputing one therefore means editing the serialization in
 * place — not re-serializing a parsed object, which would reorder fields, and
 * not hashing the bytes as they stand, which would hash the answer along with
 * the question.
 *
 * The length-preserving substitution is what keeps the version string's byte
 * count true while the digest is taken.
 */

const DUMMY = "#";

/** Where a top-level `"<label>":"<44 chars>"` sits inside a serialization. */
function locateField(
  serialization: string,
  label: string,
): { start: number; end: number } | null {
  const pattern = new RegExp(`"${label}"\\s*:\\s*"`);
  const match = pattern.exec(serialization);
  if (!match) return null;
  const start = match.index + match[0].length;
  const end = serialization.indexOf('"', start);
  if (end < 0) return null;
  return { start, end };
}

/**
 * Recompute the SAID a serialization carries, over the serialization itself.
 *
 * `labels` names every field replaced by a dummy before the digest is taken.
 * Returns null when none of them are present — an absence, which the caller
 * reports as unchecked rather than as a mismatch.
 */
export function recomputeSaid(
  serialization: string,
  labels: readonly string[] = ["d"],
): string | null {
  const fields = labels
    .map((label) => locateField(serialization, label))
    .filter((field): field is { start: number; end: number } => field !== null)
    .sort((a, b) => a.start - b.start);
  if (fields.length === 0) return null;

  let dummied = "";
  let cursor = 0;
  for (const field of fields) {
    dummied +=
      serialization.slice(cursor, field.start) +
      DUMMY.repeat(field.end - field.start);
    cursor = field.end;
  }
  dummied += serialization.slice(cursor);

  return encodeDigest(
    blake3(new TextEncoder().encode(dummied), { dkLen: 32 }),
  );
}

/**
 * The SAID of a KERI or registry event, dummying whichever fields that event
 * derives from its own digest.
 *
 * An inception derives the identifier it announces, so `i` carries the same
 * value as `d` and has to be blanked alongside it — the rest of the log names
 * an identifier established elsewhere and leaves `i` alone. Deciding from the
 * values rather than from a table of event types means a basic, non-derived
 * prefix is handled by the same line, and no event type has to be enumerated.
 */
export function recomputeEventSaid(serialization: string): string | null {
  const said = declaredSaid(serialization, "d");
  const prefix = declaredSaid(serialization, "i");
  return recomputeSaid(
    serialization,
    said !== null && said === prefix ? ["d", "i"] : ["d"],
  );
}

/** The SAID a serialization claims, without recomputing anything. */
export function declaredSaid(
  serialization: string,
  label = "d",
): string | null {
  const field = locateField(serialization, label);
  return field ? serialization.slice(field.start, field.end) : null;
}

/** Whether a serialization hashes to the identifier it carries. */
export function saidMatches(serialization: string): boolean {
  const declared = declaredSaid(serialization, "d");
  const recomputed = recomputeEventSaid(serialization);
  return declared !== null && recomputed !== null && declared === recomputed;
}
