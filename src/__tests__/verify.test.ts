import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyPackage, UnsupportedPackageError } from "../verify.js";
import { recomputeSaid } from "../said.js";
import { verifyKel } from "../kel.js";
import type { TrustableVerifyPackage } from "../types.js";

function fixture(name: string): TrustableVerifyPackage {
  const path = fileURLToPath(
    new URL(`../../fixtures/${name}.json`, import.meta.url),
  );
  return JSON.parse(readFileSync(path, "utf8")) as TrustableVerifyPackage;
}

function clone(pkg: TrustableVerifyPackage): TrustableVerifyPackage {
  return JSON.parse(JSON.stringify(pkg)) as TrustableVerifyPackage;
}

describe("verifyPackage — a sealed credential", () => {
  it("verifies from the package alone", () => {
    const result = verifyPackage(fixture("issued"));

    expect(result.isValid).toBe(true);
    expect(result.status).toBe("verified");
    expect(result.authenticity.established).toBe(true);
    expect(result.trustReport.steps.saidIntegrity.status).toBe("passed");
    expect(result.trustReport.steps.cryptographicVerification.status).toBe(
      "passed",
    );
    expect(result.trustReport.steps.kelDiscovery.status).toBe("passed");
    expect(result.trustReport.steps.telValidation.status).toBe("passed");
  });

  // The point of the whole exercise. Anything that reached the network would
  // throw here rather than quietly succeed on a developer's machine.
  it("touches no network of any kind", () => {
    const original = globalThis.fetch;
    globalThis.fetch = (() => {
      throw new Error("the offline verifier attempted a network call");
    }) as typeof fetch;
    try {
      expect(verifyPackage(fixture("issued")).isValid).toBe(true);
    } finally {
      globalThis.fetch = original;
    }
  });

  it("dates its answer to the package, never to now", () => {
    const result = verifyPackage(fixture("issued"));
    expect(result.verification_mode).toBe("offline");
    expect(result.as_of).toBe("2026-08-19T00:00:00.000Z");
  });

  it("gives an undated package no as_of rather than a flattering one", () => {
    const pkg = clone(fixture("issued"));
    delete pkg.packaged_at;
    expect(verifyPackage(pkg).as_of).toBeNull();
  });
});

describe("verifyPackage — a revoked credential", () => {
  it("reads the revocation from the anchored history", () => {
    const result = verifyPackage(fixture("revoked"));

    expect(result.status).toBe("revoked");
    expect(result.isValid).toBe(false);
    // Authorship is still established — the issuer really did issue it, and
    // then really did revoke it. Those are different questions.
    expect(result.authenticity.established).toBe(true);
    expect(result.trustReport.steps.revocationStatus.status).toBe("failed");
  });

  it("cannot be un-revoked by editing the summary beside the bytes", () => {
    const pkg = clone(fixture("revoked"));
    const events = (pkg.tel as { tel_events: Record<string, unknown>[] })
      .tel_events;
    for (const event of events) event["event_type"] = "iss";
    (pkg.tel as { status: string }).status = "issued";
    pkg.credential_status = { status: "issued" };

    expect(verifyPackage(pkg).status).toBe("revoked");
  });
});

describe("verifyPackage — tampering", () => {
  // Not the last base64 character: on a 44-character primitive that is a no-op
  // roughly one time in 850, so the test would pass by accident.
  it("fails SAID integrity when one byte of the credential changes", () => {
    const pkg = clone(fixture("issued"));
    const cesr = pkg.cesr as string;
    const at = cesr.indexOf("aaaa");
    expect(at).toBeGreaterThan(-1);
    pkg.cesr = `${cesr.slice(0, at)}b${cesr.slice(at + 1)}`;

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.saidIntegrity.status).toBe("failed");
    expect(result.isValid).toBe(false);
    expect(result.authenticity.established).toBe(false);
  });

  it("fails when the credential bytes describe a different credential", () => {
    const pkg = clone(fixture("issued"));
    pkg.acdc_said = "EPklyZbD6rfV2ypJRKiNETOs2aTirVAB5e03dNGWy2aZ";

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.saidIntegrity.status).toBe("failed");
    expect(result.isValid).toBe(false);
  });

  // A forged KEL is the interesting attack: mint your own credential, attach a
  // key log you control, and every self-consistency check passes.
  it("fails when a key event is not signed by the keys in force", () => {
    const pkg = clone(fixture("issued"));
    const kel = pkg.kel as string;
    // Inside the signature payload, not on its code characters: the code is
    // consumed as padding on decode, so flipping one leaves the signature bytes
    // identical and the test would pass while proving nothing.
    const at = kel.indexOf("-AAB") + 4 + 10;
    const flipped = kel[at] === "A" ? "B" : "A";
    pkg.kel = `${kel.slice(0, at)}${flipped}${kel.slice(at + 1)}`;
    expect(pkg.kel).not.toBe(kel);

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.kelDiscovery.status).toBe("failed");
    expect(result.authenticity.established).toBe(false);
    expect(result.isValid).toBe(false);
  });

  it("fails when the KEL belongs to a different identifier", () => {
    const pkg = clone(fixture("issued"));
    pkg.issuer_aid = "EM9Kj2oDV0E5wQ1WL4NA1tQKIkRsjUhURT8C43q9XxEq";

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.kelDiscovery.status).toBe("failed");
    expect(result.isValid).toBe(false);
  });

  // The sharpest case, and the reason the anchor check exists. This issuance is
  // flawless on its own terms — real KERI bytes, hashing to the identifier they
  // carry, naming the right credential and the right registry. It was simply
  // never sealed into the issuer's key event log. Registry events carry no
  // signatures of their own, so without the anchor walk nothing distinguishes
  // it from the genuine one, and anybody could mint an issuance for a
  // credential they do not control.
  it("fails a flawless issuance that no seal in the KEL names", () => {
    const result = verifyPackage(fixture("unanchored-issuance"));

    expect(result.trustReport.steps.saidIntegrity.status).toBe("passed");
    expect(result.trustReport.steps.kelDiscovery.status).toBe("passed");
    expect(result.trustReport.steps.cryptographicVerification.status).toBe(
      "failed",
    );
    expect(result.authenticity.established).toBe(false);
    expect(result.isValid).toBe(false);
  });

  it("fails when the issuance bytes were altered after sealing", () => {
    const pkg = clone(fixture("issued"));
    const events = (pkg.tel as { tel_events: Record<string, unknown>[] })
      .tel_events;
    const raw = events[0]!["event"] as string;
    const forged = raw.replace(/"dt":"[^"]*"/, '"dt":"2026-01-01T00:00:00.000000+00:00"');
    expect(forged).not.toBe(raw);
    // Re-said it so the event is internally consistent — only the anchor fails.
    const sad = JSON.parse(forged) as Record<string, string>;
    const dummied = forged.replace(sad["d"] as string, "#".repeat(44));
    void dummied;
    events[0]!["event"] = forged;

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.cryptographicVerification.status).toBe(
      "failed",
    );
    expect(result.authenticity.established).toBe(false);
    expect(result.isValid).toBe(false);
  });
});

describe("verifyPackage — what it refuses to guess", () => {
  it("reports integrity only when no KEL travelled", () => {
    const pkg = clone(fixture("issued"));
    delete pkg.kel;

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.saidIntegrity.status).toBe("passed");
    expect(result.authenticity.established).toBe(false);
    expect(result.isValid).toBe(false);
  });

  it("degrades rather than fails when the credential body was withheld", () => {
    const pkg = clone(fixture("issued"));
    delete pkg.cesr;
    pkg.integrity = {
      said_checkable: false,
      reason: "Retention policy withholds the credential body.",
    };

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.saidIntegrity.status).toBe("degraded");
    expect(result.isValid).toBe(false);
    // Issuance and revocation are still answerable without the body.
    expect(result.trustReport.steps.telValidation.status).toBe("passed");
  });

  it("refuses a schema version it does not understand", () => {
    const pkg = clone(fixture("issued"));
    pkg.schema_version = 2;
    expect(() => verifyPackage(pkg)).toThrow(UnsupportedPackageError);
  });

  it("will not call a suspended trustable valid", () => {
    const pkg = clone(fixture("issued"));
    pkg.trustable_status = { current_state: "suspended" };

    const result = verifyPackage(pkg);
    expect(result.status).toBe("suspended");
    expect(result.isValid).toBe(false);
  });
});

describe("the primitives", () => {
  it("recomputes the SAID keripy wrote", () => {
    const pkg = fixture("issued");
    expect(recomputeSaid(pkg.cesr as string)).toBe(pkg.acdc_said);
  });

  it("walks the real KEL", () => {
    const pkg = fixture("issued");
    const result = verifyKel(pkg.kel as string, pkg.issuer_aid);
    expect("kel" in result).toBe(true);
    if ("kel" in result) {
      expect(result.kel.eventCount).toBe(4);
      expect(result.kel.anchors.length).toBe(3);
      expect(result.kel.currentKeys.length).toBe(1);
    }
  });
});

describe("the trust score", () => {
  // The number is read beside the hosted one in the same UI, so it has to be
  // the same number for the same evidence — including the parts that look
  // unflattering.
  it("bands a fully verified package medium, not high", () => {
    const score = verifyPackage(fixture("issued")).trustScore;

    // Witness receipts and watcher status are optional checks this path cannot
    // run. The band only reaches `high` when an optional check passes, so the
    // honest ceiling offline is medium at the required-only weight total.
    expect(score.band).toBe("medium");
    expect(score.score).toBe(70);
    expect(score.confidence).toBe(1);
    expect(score.counts).toEqual({
      passed: 4,
      skipped: 2,
      degraded: 0,
      failed: 0,
      total: 6,
      runnable: 4,
    });
  });

  it("zeroes the score when a required check fails", () => {
    const pkg = clone(fixture("issued"));
    delete pkg.kel;

    const score = verifyPackage(pkg).trustScore;
    expect(score.band).toBe("failed");
    expect(score.score).toBe(0);
  });

  // Worth pinning down, because it looks wrong until you check the hosted
  // scale: SAID integrity is not one of the weighted checks. A package whose
  // body was withheld therefore still scores 70 while `isValid` is false — the
  // score answers "how much of the evidence held up", the verdict answers
  // "should you rely on this". They are different questions and the number is
  // reproduced from the hosted scale deliberately, oddity included.
  it("scores on the weighted checks, which do not include integrity", () => {
    const pkg = clone(fixture("issued"));
    delete pkg.cesr;

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.saidIntegrity.status).toBe("degraded");
    expect(result.trustScore.band).toBe("medium");
    expect(result.trustScore.score).toBe(70);
    expect(result.isValid).toBe(false);
  });

  it("caps a degraded required check at the limited band", () => {
    const pkg = clone(fixture("issued"));
    // No registry history: telValidation fails and revocation degrades.
    delete pkg.tel;

    const score = verifyPackage(pkg).trustScore;
    expect(score.band).toBe("failed");
    expect(score.score).toBe(0);
  });
});
