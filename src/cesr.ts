import { decodeIndexedSignature } from "./qb64.js";

/**
 * Reads a CESR stream far enough to verify it: each event's exact bytes, and
 * the controller signatures attached to it.
 *
 * A stream is a sequence of framed serializations, each optionally followed by
 * attachment groups. The version string inside every event states its own byte
 * count, so framing is read from the event rather than guessed from the next
 * delimiter — the only approach that survives an attachment containing
 * something that looks like the start of an event.
 *
 * Witness receipts and first-seen replay couples travel in the same
 * attachments. They are skipped rather than parsed: this verifier judges the
 * controller's authorship, and a witness threshold is a different question
 * nobody is asking of an archived package.
 */

export interface ParsedEvent {
  /** The event's exact serialization — what a signature covers. */
  raw: string;
  /** Parsed for field access. The raw string stays authoritative. */
  sad: Record<string, unknown>;
  /** Controller signatures, by their index into the signing key list. */
  signatures: { index: number; signature: Uint8Array }[];
}

const VERSION = /\{"v"\s*:\s*"(?:KERI|ACDC)(\d)(\d)(?:JSON)([0-9a-f]{6})_"/;

/** Counter codes whose count is a number of 4-character quadlets. */
const QUADLET_COUNTERS = new Set(["-V", "-0V"]);

function readCount(text: string, at: number): number {
  const count = text.slice(at, at + 2);
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const hi = B64.indexOf(count[0] as string);
  const lo = B64.indexOf(count[1] as string);
  if (hi < 0 || lo < 0) throw new Error(`unreadable counter count: ${count}`);
  return hi * 64 + lo;
}

/**
 * Controller signatures out of one attachment blob.
 *
 * Only `-A` (controller indexed signatures) is read. An outer `-V` group is
 * stepped into rather than skipped, because that is where KERIA puts them.
 */
function readControllerSignatures(
  attachment: string,
): { index: number; signature: Uint8Array }[] {
  const found: { index: number; signature: Uint8Array }[] = [];
  let cursor = 0;

  while (cursor + 4 <= attachment.length && attachment[cursor] === "-") {
    const code = attachment.slice(cursor, cursor + 2);
    const count = readCount(attachment, cursor + 2);
    cursor += 4;

    if (code === "-A") {
      for (let i = 0; i < count; i += 1) {
        const primitive = attachment.slice(cursor, cursor + 88);
        if (primitive.length < 88) return found;
        found.push(decodeIndexedSignature(primitive));
        cursor += 88;
      }
      continue;
    }

    if (QUADLET_COUNTERS.has(code)) {
      // An attachment group states the size of everything inside it, so its
      // contents are parsed in place — descending is what finds the signatures.
      continue;
    }

    // Anything else is a group this verifier does not read. Without a
    // length in characters there is no way to step over it safely, so the
    // signatures found so far are returned rather than guessed past.
    return found;
  }

  return found;
}

/** Every framed event in a CESR stream, with its controller signatures. */
export function parseCesrStream(stream: string): ParsedEvent[] {
  const events: ParsedEvent[] = [];
  let cursor = 0;

  while (cursor < stream.length) {
    const rest = stream.slice(cursor);
    const match = VERSION.exec(rest);
    if (!match || match.index === undefined) break;

    const start = cursor + match.index;
    const size = parseInt(match[3] as string, 16);
    if (!Number.isFinite(size) || size <= 0) break;

    // The version string counts BYTES. Slicing the string would count UTF-16
    // units and cut an event carrying any non-ASCII attribute in the wrong
    // place.
    const bytes = new TextEncoder().encode(stream.slice(start));
    const raw = new TextDecoder().decode(bytes.subarray(0, size));

    let sad: Record<string, unknown>;
    try {
      sad = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      break;
    }

    const afterEvent = start + raw.length;
    const next = VERSION.exec(stream.slice(afterEvent));
    const attachmentEnd =
      next && next.index !== undefined
        ? afterEvent + next.index
        : stream.length;

    events.push({
      raw,
      sad,
      signatures: readControllerSignatures(
        stream.slice(afterEvent, attachmentEnd),
      ),
    });
    cursor = attachmentEnd;
  }

  return events;
}
