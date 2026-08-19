import { declaredSaid, recomputeEventSaid } from "./said.js";
import type { KelSeal } from "./kel.js";

/**
 * Reads the registry's history of a credential, and decides which of it the
 * issuer actually stood behind.
 *
 * Transaction events are not signed. What binds one to the issuer is a seal in
 * their key event log naming that event's digest — so an event only counts once
 * its SAID has been recomputed from its own bytes AND found among the anchors
 * of a KEL whose signatures verified. Anything else in the log is a claim the
 * package makes about itself.
 */

export interface TelEvent {
  type: string;
  said: string;
  /** Credential or registry the event is about — `i` in the serialization. */
  subject: string;
  sequence: number;
  anchored: boolean;
}

export interface TelReading {
  events: TelEvent[];
  /** Events whose SAID was matched to a verified KEL seal. */
  anchoredCount: number;
  /** `issued` / `revoked` from the last ANCHORED event, else null. */
  status: "issued" | "revoked" | null;
}

/** A packaged TEL event, as the export writes it. */
interface PackagedTelEvent {
  event?: unknown;
  event_type?: unknown;
  said?: unknown;
  sn?: unknown;
}

/** The events out of whichever shape the package carries. */
export function packagedTelEvents(tel: unknown): PackagedTelEvent[] {
  if (Array.isArray(tel)) return tel as PackagedTelEvent[];
  if (!tel || typeof tel !== "object") return [];
  const container = tel as { tel_events?: unknown; events?: unknown };
  const list = Array.isArray(container.tel_events)
    ? container.tel_events
    : container.events;
  return Array.isArray(list) ? (list as PackagedTelEvent[]) : [];
}

/**
 * Read a packaged TEL against a set of verified KEL anchors.
 *
 * An event with no serialization is reported and left unanchored — its summary
 * fields are the package describing itself, and a digest cannot be taken of a
 * description.
 */
export function readTel(tel: unknown, anchors: KelSeal[]): TelReading {
  const anchoredSaids = new Set(
    anchors
      .map((seal) => seal.d)
      .filter((said): said is string => typeof said === "string"),
  );

  const events: TelEvent[] = [];

  for (const packaged of packagedTelEvents(tel)) {
    const raw = typeof packaged.event === "string" ? packaged.event : null;
    if (raw === null) {
      events.push({
        type: typeof packaged.event_type === "string" ? packaged.event_type : "",
        said: typeof packaged.said === "string" ? packaged.said : "",
        subject: "",
        sequence: Number.NaN,
        anchored: false,
      });
      continue;
    }

    let sad: Record<string, unknown>;
    try {
      sad = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }

    // The SAID is recomputed from the bytes, never read off the summary beside
    // them: the anchor is matched on this value, so taking the package's word
    // for it would let any event claim a seal that names a different one.
    const recomputed = recomputeEventSaid(raw);
    const declared = declaredSaid(raw);
    const intact = recomputed !== null && recomputed === declared;

    events.push({
      type: typeof sad["t"] === "string" ? (sad["t"] as string) : "",
      said: recomputed ?? "",
      subject: typeof sad["i"] === "string" ? (sad["i"] as string) : "",
      sequence: parseInt(
        typeof sad["s"] === "string" ? (sad["s"] as string) : "",
        16,
      ),
      anchored: intact && recomputed !== null && anchoredSaids.has(recomputed),
    });
  }

  // Order by sequence so a package that lists its events out of order cannot
  // present an old issuance as the current state.
  const ordered = [...events].sort((a, b) => {
    if (Number.isNaN(a.sequence) || Number.isNaN(b.sequence)) return 0;
    return a.sequence - b.sequence;
  });

  const lastAnchored = [...ordered].reverse().find((event) => event.anchored);
  const status =
    lastAnchored?.type === "rev"
      ? "revoked"
      : lastAnchored?.type === "iss"
        ? "issued"
        : null;

  return {
    events: ordered,
    anchoredCount: ordered.filter((event) => event.anchored).length,
    status,
  };
}

/** The anchored issuance of a specific credential, if the log carries one. */
export function anchoredIssuance(
  reading: TelReading,
  credentialSaid: string,
): TelEvent | null {
  return (
    reading.events.find(
      (event) =>
        event.anchored && event.type === "iss" && event.subject === credentialSaid,
    ) ?? null
  );
}
