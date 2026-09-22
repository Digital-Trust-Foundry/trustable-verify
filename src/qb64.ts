/**
 * The slice of CESR this verifier needs: decoding the fixed-size primitives a
 * KEL and an ACDC are built from, and encoding a digest back into one.
 *
 * A CESR primitive is `code || base64url(pad || raw)` with the leading `ps`
 * characters of the base64 overwritten by the code, where `ps` is the number of
 * pad bytes the raw length needs. For every primitive here the code is exactly
 * as long as that pad, which is what makes the round trip a slice rather than a
 * bit-level operation.
 *
 * Getting the pad wrong is the classic way to produce a 44-character string
 * that looks like a SAID and is not one: base64 of the digest alone encodes
 * different bytes than base64 of a zero byte followed by the digest.
 */

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64_INDEX = new Map<string, number>(
  [...B64].map((character, index) => [character, index]),
);

/** Pad bytes a raw value of this length needs before base64 encoding. */
export function padSize(rawLength: number): number {
  return (3 - (rawLength % 3)) % 3;
}

export function base64UrlToBytes(text: string): Uint8Array {
  if (text.length % 4 !== 0) {
    throw new Error(`base64url length ${text.length} is not a multiple of 4`);
  }
  const out = new Uint8Array((text.length / 4) * 3);
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    let bits = 0;
    for (let j = 0; j < 4; j += 1) {
      const value = B64_INDEX.get(text[i + j] as string);
      if (value === undefined) {
        throw new Error(`not a base64url character: ${String(text[i + j])}`);
      }
      bits = (bits << 6) | value;
    }
    out[o] = (bits >> 16) & 0xff;
    out[o + 1] = (bits >> 8) & 0xff;
    out[o + 2] = bits & 0xff;
    o += 3;
  }
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] as number;
    const b = i + 1 < bytes.length ? (bytes[i + 1] as number) : 0;
    const c = i + 2 < bytes.length ? (bytes[i + 2] as number) : 0;
    const bits = (a << 16) | (b << 8) | c;
    text +=
      (B64[(bits >> 18) & 0x3f] as string) +
      (B64[(bits >> 12) & 0x3f] as string) +
      (B64[(bits >> 6) & 0x3f] as string) +
      (B64[bits & 0x3f] as string);
  }
  return text;
}

/**
 * Raw bytes out of a qb64 primitive whose code is as long as its pad — every
 * primitive this verifier reads: 32-byte keys and digests under a one-character
 * code, 64-byte signatures under a two-character one.
 */
export function decodeQb64(text: string, rawLength: number): Uint8Array {
  const pad = padSize(rawLength);
  // The code overwrites the pad characters rather than adding to them, so the
  // primitive is exactly as long as the base64 of `pad || raw`.
  const expected = ((pad + rawLength) / 3) * 4;
  if (text.length !== expected) {
    throw new Error(
      `expected a ${expected}-character primitive for ${rawLength} raw bytes, got ${text.length}`,
    );
  }
  // The code characters are re-pad before decoding: they occupy exactly the
  // positions the pad bytes encoded into, so putting zeros back recovers the
  // original alignment.
  const decoded = base64UrlToBytes("A".repeat(pad) + text.slice(pad));
  return decoded.slice(pad);
}

/** A 32-byte digest as a CESR BLAKE3-256 primitive (`E`). */
export function encodeDigest(raw: Uint8Array): string {
  if (raw.length !== 32) {
    throw new Error(`a BLAKE3-256 digest is 32 bytes, got ${raw.length}`);
  }
  const padded = new Uint8Array(33);
  padded.set(raw, 1);
  return `E${bytesToBase64Url(padded).slice(1)}`;
}

/** Ed25519 public key (`D`, or `B` for a non-transferable one). */
export function decodeVerkey(qb64: string): Uint8Array {
  const code = qb64[0];
  if (code !== "D" && code !== "B") {
    throw new Error(`not an Ed25519 public key primitive: ${qb64.slice(0, 4)}`);
  }
  return decodeQb64(qb64, 32);
}

/**
 * How long an Ed25519 indexed signature is, read off its code.
 *
 * Two forms carry the same 64-byte signature. `A`/`B` are 88 characters: a
 * one-character code and a one-character index, good for indexes below 64.
 * `2A`/`2B` are 92: a two-character code, a two-character index and a
 * two-character prior-index. Signify writes the second form whenever the
 * index and the prior index differ — which is to say for any identifier
 * that has rotated, and every paired wallet rotates. A verifier that reads
 * only the first form fails every signature such an identifier makes.
 */
export function indexedSignatureLength(qb64: string): 88 | 92 {
  return qb64[0] === "2" ? 92 : 88;
}

/** Ed25519 indexed signature, in either the short or the big-index form. */
export function decodeIndexedSignature(qb64: string): {
  index: number;
  signature: Uint8Array;
} {
  if (qb64[0] === "A" || qb64[0] === "B") {
    const index = B64_INDEX.get(qb64[1] as string);
    if (index === undefined) {
      throw new Error(`unreadable signature index: ${String(qb64[1])}`);
    }
    return { index, signature: decodeQb64(qb64, 64) };
  }
  const code = qb64.slice(0, 2);
  if (code !== "2A" && code !== "2B") {
    throw new Error(`not an Ed25519 indexed signature: ${qb64.slice(0, 4)}`);
  }
  if (qb64.length !== 92) {
    throw new Error(
      `expected a 92-character big-index signature, got ${qb64.length}`,
    );
  }
  // The index is the first two soft characters; the two after it are the
  // prior-next index, which says where the key sat before rotation and plays
  // no part in checking the signature against the keys in force.
  const index = base64Int(qb64.slice(2, 4));
  if (Number.isNaN(index)) {
    throw new Error(`unreadable signature index: ${qb64.slice(2, 4)}`);
  }
  // Six characters of code and soft part stand where the short form has two,
  // so the extra quadlet is dropped and the rest decodes exactly as before.
  return { index, signature: decodeQb64(`AA${qb64.slice(6)}`, 64) };
}

/** A base64url string read as a big-endian integer, NaN when unreadable. */
export function base64Int(text: string): number {
  let value = 0;
  for (const char of text) {
    const digit = B64_INDEX.get(char);
    if (digit === undefined) return Number.NaN;
    value = value * 64 + digit;
  }
  return value;
}
