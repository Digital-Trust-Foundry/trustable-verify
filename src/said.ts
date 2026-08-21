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

/** The 44-character dummy a Blake3-256 SAID field is blanked to. */
const DUMMY_SAID = DUMMY.repeat(44);

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** A big-endian base64 integer of a fixed width, as a 2.0 version string writes its size. */
function base64Size(value: number, width = 4): string {
  let rest = value;
  let text = "";
  for (let i = 0; i < width; i += 1) {
    text = B64[rest % 64] + text;
    rest = Math.floor(rest / 64);
  }
  return text;
}

/** An ACDC 2.0 version string, whose size is base64 and whose terminator is `.`. */
const ACDC_2 = /"v"\s*:\s*"ACDC[A-Za-z0-9_-]{6}JSON([A-Za-z0-9_-]{4})\."/;

/**
 * The extent of a `"<label>":{…}` value, brace-matched.
 *
 * A section holds nested objects and strings that may hold braces of their own,
 * so counting them without tracking string state would end the section early
 * and hash a fragment.
 */
function locateSection(
  serialization: string,
  label: string,
): { start: number; end: number } | null {
  const opening = new RegExp(`"${label}"\\s*:\\s*\\{`);
  const match = opening.exec(serialization);
  if (!match) return null;

  const start = match.index + match[0].length - 1;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < serialization.length; i += 1) {
    const character = serialization[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (character === "{") depth += 1;
    else if (character === "}") {
      depth -= 1;
      if (depth === 0) return { start, end: i + 1 };
    }
  }
  return null;
}

/**
 * A section's own identifier, derived from the section's bytes.
 *
 * Derived and never read off the section, and that is the whole security of an
 * edge. The compact form a 2.0 identifier is computed over carries only this
 * digest, so a reader that trusted the `d` a section states would accept a
 * section whose contents had been rewritten underneath an untouched `d` — an
 * approval edited to say it approves something else, still hashing to the
 * identifier it was issued under.
 *
 * Null when the section carries no `d`. Such a section has no identifier to
 * stand in for it and stays expanded, which is what keripy does with an
 * attribute block that was never given one.
 */
function sectionSaid(section: string): string | null {
  const field = locateField(section, "d");
  if (!field) return null;
  const dummied =
    section.slice(0, field.start) + DUMMY_SAID + section.slice(field.end);
  return encodeDigest(blake3(new TextEncoder().encode(dummied), { dkLen: 32 }));
}

/**
 * The serialization a 2.0 identifier is actually computed over.
 *
 * ACDC 2.0 derives a credential's identifier from its MOST COMPACT form: every
 * section that has an identifier of its own is replaced by that identifier, and
 * the version string restates the byte count of what is left. That is what lets
 * an expanded credential, a partially disclosed one and a fully compact one all
 * carry the same identifier — the point of graduated disclosure, and the reason
 * hashing the bytes as they arrive gives an answer that is simply not the one
 * the issuer computed.
 *
 * 1.0 has none of this. It derives its identifier from the serialization in
 * front of you, which is why everything below this line is version-gated rather
 * than applied hopefully to both.
 *
 * Null when a section cannot be reduced the way the issuer would have reduced
 * it — a schema carried inline as an object rather than as its SAID. Nothing
 * here mints one, so this is a shape we have not seen rather than one we
 * handle; null reports the identifier as unchecked instead of announcing a
 * mismatch that is really our own ignorance.
 */
function compactForm(serialization: string): string | null {
  // Later labels first, so replacing one does not move the offsets of another.
  for (const label of ["r", "e", "a"]) {
    const section = locateSection(serialization, label);
    if (!section) continue;
    const said = sectionSaid(serialization.slice(section.start, section.end));
    if (said === null) continue;
    serialization =
      serialization.slice(0, section.start) +
      `"${said}"` +
      serialization.slice(section.end);
  }
  if (locateSection(serialization, "s")) return null;

  const field = locateField(serialization, "d");
  if (!field) return null;
  const dummied =
    serialization.slice(0, field.start) +
    DUMMY.repeat(field.end - field.start) +
    serialization.slice(field.end);

  // The size the issuer stated is the size of THIS string, not of the expanded
  // one it arrived as. Counted in bytes, because that is what a version string
  // counts and what a non-ASCII attribute would otherwise miscount.
  const size = new TextEncoder().encode(dummied).length;
  return dummied.replace(ACDC_2, (whole, stated: string) =>
    whole.replace(stated + ".", base64Size(size) + "."),
  );
}

/**
 * Recompute the SAID a serialization carries, over the serialization itself.
 *
 * `labels` names every field replaced by a dummy before the digest is taken.
 * Returns null when none of them are present — an absence, which the caller
 * reports as unchecked rather than as a mismatch.
 *
 * An ACDC framed 2.0 takes the compact route above instead: its identifier was
 * never a digest of the bytes it ships as. Key events are untouched by this —
 * they are 2.0 too, and they are not compactable, so they keep deriving their
 * identifier from the serialization they arrive in.
 */
export function recomputeSaid(
  serialization: string,
  labels: readonly string[] = ["d"],
): string | null {
  if (
    labels.length === 1 &&
    labels[0] === "d" &&
    ACDC_2.test(serialization.slice(0, 64))
  ) {
    const compact = compactForm(serialization);
    return compact === null
      ? null
      : encodeDigest(blake3(new TextEncoder().encode(compact), { dkLen: 32 }));
  }

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

  return encodeDigest(blake3(new TextEncoder().encode(dummied), { dkLen: 32 }));
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
