import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { verifyPackage, UnsupportedPackageError } from "../verify.js";
import { recomputeSaid } from "../said.js";
import { verifyKel } from "../kel.js";
import { parseCesrStream } from "../cesr.js";
import { satisfiedRound } from "../approvals.js";
import { boundPolicy } from "../acdc.js";

/** A framed ACDC carrying one signature policy, for reading the policy back. */
function policyCesr(threshold: number): string {
  const sad = {
    v: "",
    d: "E".padEnd(44, "0"),
    i: "E".padEnd(44, "1"),
    a: {
      signature_policy: {
        threshold,
        candidates: [{ actor_aid: "EAlice", role: "officer" }],
      },
    },
  };
  const framed = (size: number) =>
    JSON.stringify({
      ...sad,
      v: `ACDC10JSON${size.toString(16).padStart(6, "0")}_`,
    });
  let size = Buffer.byteLength(framed(0), "utf8");
  for (let i = 0; i < 4; i += 1) size = Buffer.byteLength(framed(size), "utf8");
  return framed(size);
}
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

describe("the package header must agree with the credential", () => {
  // Every check below the header keys off these two fields, so a package free
  // to name a credential or an issuer its ACDC does not would have the key-log
  // walk and the anchor match vouching for something other than what is being
  // read.
  it("rejects a package whose ACDC names a different credential", () => {
    const pkg = clone(fixture("issued"));
    (pkg.acdc as Record<string, unknown>)["d"] = "EPklyZbD6rfV2ypJRKiNETOs2aTirVAB5e03dNGWy2aZ";

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.structureValidation.status).toBe("failed");
    expect(result.isValid).toBe(false);
  });

  it("rejects a package whose ACDC names a different issuer", () => {
    const pkg = clone(fixture("issued"));
    (pkg.acdc as Record<string, unknown>)["i"] = "EM9Kj2oDV0E5wQ1WL4NA1tQKIkRsjUhURT8C43q9XxEq";

    const result = verifyPackage(pkg);
    expect(result.trustReport.steps.structureValidation.status).toBe("failed");
    expect(result.isValid).toBe(false);
  });
});

describe("the approvals the credential itself required", () => {
  // The requirement lives inside the envelope the SAID is computed over, so a
  // package for a Trustable that needed three signatures cannot be edited to
  // look like one that needed none — the edit breaks the credential.
  it("refuses a credential whose declared approvals cannot be shown", () => {
    const result = verifyPackage(fixture("multisig"));

    expect(result.trustReport.steps.saidIntegrity.status).toBe("passed");
    expect(result.authenticity.established).toBe(true);
    expect(result.trustReport.steps.approvalCompletion?.status).toBe("failed");
    expect(result.trustReport.steps.approvalCompletion?.details).toContain("3");
    expect(result.isValid).toBe(false);
  });

  // The decisive part is the named signer set, not the count. "These signers
  // and no others" with a threshold of one is a 1-of-N approval: a specific
  // person still has to approve, and the credential is minted before anyone is
  // asked. Reading only the threshold waves that straight through — which is
  // the case a product about officer authority cannot afford to get wrong.
  it("refuses a 1-of-N policy, where the count alone looks satisfied", () => {
    const result = verifyPackage(fixture("one-of-n"));

    expect(result.trustReport.steps.approvalCompletion?.status).toBe("failed");
    expect(result.trustReport.steps.approvalCompletion?.details).toContain(
      "named signer set",
    );
    expect(result.isValid).toBe(false);
  });

  it("passes when the credential names a threshold of one", () => {
    const result = verifyPackage(fixture("issued"));

    expect(result.trustReport.steps.approvalCompletion?.status).toBe("passed");
    expect(result.isValid).toBe(true);
  });

  // A credential minted before the policy was bound cannot speak to this. It is
  // not proof of a violation and not proof of compliance, so it degrades rather
  // than condemns — and does not reach a verified verdict either.
  // A credential minted before the policy was bound cannot speak to this. It is
  // not proof of a violation and not proof of compliance, so it degrades rather
  // than condemns — and does not reach a verified verdict either.
  //
  // This is a real credential from before the change, not one edited to look
  // like it: removing the field from a package would break the SAID, which is
  // exactly what binding it was for.
  it("reports a credential from before the change as unstated", () => {
    const result = verifyPackage(fixture("legacy-no-policy"));

    expect(result.trustReport.steps.saidIntegrity.status).toBe("passed");
    expect(result.authenticity.established).toBe(true);
    expect(result.trustReport.steps.approvalCompletion?.status).toBe(
      "degraded",
    );
    expect(result.isValid).toBe(false);
  });
});

describe("the approvals themselves, proven from their own credentials", () => {
  // Acceptance 1. The whole point of the change: a Trustable that required a
  // round of approvals reaches a verified verdict, from the bytes alone.
  it("verifies an approved multi-signer Trustable offline", () => {
    const original = globalThis.fetch;
    globalThis.fetch = (() => {
      throw new Error("the offline verifier attempted a network call");
    }) as typeof fetch;
    try {
      const result = verifyPackage(fixture("approved"));

      expect(result.trustReport.steps.approvalCompletion?.status).toBe(
        "passed",
      );
      expect(result.isValid).toBe(true);
      expect(result.status).toBe("verified");
    } finally {
      globalThis.fetch = original;
    }
  });

  // Acceptance 2. A threshold is not a formality: take one approval away and
  // the package says which requirement went unmet rather than failing vaguely.
  it("fails, and names the threshold, when an approval is removed", () => {
    const pkg = clone(fixture("approved"));
    pkg.approvals = pkg.approvals!.slice(0, 1);

    const result = verifyPackage(pkg);
    const details = result.trustReport.steps.approvalCompletion?.details ?? "";

    expect(result.trustReport.steps.approvalCompletion?.status).toBe("failed");
    expect(details).toContain("requires 2 approvals");
    expect(details).toContain("1 could be proven");
    expect(result.isValid).toBe(false);
  });

  // Acceptance 3. An approval is an approval OF something. A genuine credential
  // that approves a different Trustable is still a genuine credential — it just
  // has nothing to say about this one.
  it("does not count an approval that chains to another credential", () => {
    const pkg = clone(fixture("approvals-rejected"));
    // Carol's approval is the first of the two, and hers is the one whose edge
    // points elsewhere.
    pkg.approvals = pkg.approvals!.slice(0, 1);

    const result = verifyPackage(pkg);
    const details = result.trustReport.steps.approvalCompletion?.details ?? "";

    expect(result.trustReport.steps.approvalCompletion?.status).toBe("failed");
    expect(details).toContain("chains to");
    expect(details).toContain("0 could be proven");
    expect(result.isValid).toBe(false);
  });

  // Acceptance 4. Anyone can mint a credential saying they approved something.
  // What makes it evidence is the signer's own key log sealing its issuance.
  it("does not count an approval whose issuance is unanchored", () => {
    const pkg = clone(fixture("approvals-rejected"));
    pkg.approvals = pkg.approvals!.slice(1);

    const result = verifyPackage(pkg);
    const details = result.trustReport.steps.approvalCompletion?.details ?? "";

    expect(result.trustReport.steps.approvalCompletion?.status).toBe("failed");
    expect(details).toContain("No issuance of this approval is sealed");
    expect(result.isValid).toBe(false);
  });

  // The bytes decide who signed. A package is free to label an approval however
  // it likes, and the label is checked against the credential rather than
  // believed — otherwise a single signer's approval could be presented twice
  // under two names and satisfy a two-of-two.
  it("rejects an approval the package attributes to the wrong signer", () => {
    const pkg = clone(fixture("approved"));
    pkg.approvals![1] = {
      ...pkg.approvals![0],
      issuer_aid: pkg.approvals![1]!.issuer_aid,
    };

    const result = verifyPackage(pkg);
    const details = result.trustReport.steps.approvalCompletion?.details ?? "";

    expect(result.trustReport.steps.approvalCompletion?.status).toBe("failed");
    expect(details).toContain("attributes this approval to");
    expect(result.isValid).toBe(false);
  });

  // Duplicating one signer's approval is the cheapest attack on a threshold,
  // and the answer is that a threshold counts signers, not credentials.
  it("counts a signer once, however many times their approval appears", () => {
    const pkg = clone(fixture("approved"));
    pkg.approvals = [pkg.approvals![0]!, pkg.approvals![0]!];

    const result = verifyPackage(pkg);

    expect(result.trustReport.steps.approvalCompletion?.status).toBe("failed");
    expect(
      result.trustReport.steps.approvalCompletion?.details,
    ).toContain("1 could be proven");
  });

  // A threshold describes one round. Two separate one-signer rounds are not a
  // two-signer round, and adding their votes together would say they were.
  // Checked on the counting directly: rewriting a round id in a package would
  // break the credential's identifier long before the count was reached.
  it("does not add up approvals cast in different rounds", () => {
    const candidates = ["EAlice", "EBob"];
    const twoRounds = satisfiedRound(
      [
        { acdcSaid: "EA1", issuerAid: "EAlice", roundId: "round-one" },
        { acdcSaid: "EB1", issuerAid: "EBob", roundId: "round-two" },
      ],
      2,
      candidates,
    );
    expect(twoRounds.met).toBe(false);
    expect(twoRounds.best).toBe(1);

    const oneRound = satisfiedRound(
      [
        { acdcSaid: "EA1", issuerAid: "EAlice", roundId: "round-one" },
        { acdcSaid: "EB1", issuerAid: "EBob", roundId: "round-one" },
      ],
      2,
      candidates,
    );
    expect(oneRound.met).toBe(true);
  });

  // Only the signers the credential names. An approval from someone outside the
  // set is a real credential about this Trustable, and still not a vote the
  // policy asked for.
  it("counts only the signers the policy names", () => {
    const outsider = satisfiedRound(
      [
        { acdcSaid: "EA1", issuerAid: "EAlice", roundId: "r" },
        { acdcSaid: "EX1", issuerAid: "EStranger", roundId: "r" },
      ],
      2,
      ["EAlice", "EBob"],
    );
    expect(outsider.met).toBe(false);
    expect(outsider.best).toBe(1);
  });
});

describe("a threshold that is not a count of signatures", () => {
  // Zero is the dangerous one: with a named signer set it would make the round
  // both required and satisfied, passing a credential nobody approved.
  it("reads a zero threshold as one approval", () => {
    const zero = satisfiedRound([], 0, ["EAlice"]);
    expect(zero.met).toBe(true);

    expect(boundPolicy(policyCesr(0))?.threshold).toBe(1);
    expect(boundPolicy(policyCesr(-2))?.threshold).toBe(1);
    expect(boundPolicy(policyCesr(2.5))?.threshold).toBe(1);
    expect(boundPolicy(policyCesr(3))?.threshold).toBe(3);
  });
});

describe("a key event log framed the KERI 2.0 way", () => {
  /**
   * The framing the platform's KERIA actually emits.
   *
   * A version string states one thing framing needs — the event's own byte
   * count — and 2.0 states it in base64 closed by `.` where 1.0 used six hex
   * digits closed by `_`. Reading only the second was not a partial answer: a
   * log of 2.0 events framed as nothing at all, and the report said the issuer
   * had no key state rather than that its key state could not be read, which
   * is a well-formed credential shown to a relying party as unverifiable.
   */
  const log = JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../../fixtures/keri-2.0-kel.json", import.meta.url)),
      "utf8",
    ),
  ) as { issuer_aid: string; kel: string };

  it("frames every event, with the signature attached to each", () => {
    const events = parseCesrStream(log.kel);

    expect(events).toHaveLength(4);
    expect(events.map((event) => event.sad["t"])).toEqual([
      "icp",
      "ixn",
      "ixn",
      "ixn",
    ]);
    // One controller signature each. A size read wrongly would still frame
    // something — it is the attachment boundary that stops making sense.
    expect(events.map((event) => event.signatures.length)).toEqual([1, 1, 1, 1]);
  });

  it("verifies the key state and finds every anchored seal", () => {
    const result = verifyKel(log.kel, log.issuer_aid);

    expect("failure" in result ? result.failure.reason : null).toBeNull();
    if ("failure" in result) return;
    expect(result.kel.anchors).toHaveLength(3);
  });

  it("still reads the 1.0 framing beside it", () => {
    // The two spellings live in the same stream format and a verifier that
    // learned the new one at the cost of the old would break every package
    // already archived.
    const events = parseCesrStream(fixture("issued").kel as string);

    expect(events.length).toBeGreaterThan(0);
    expect(events[0]?.sad["t"]).toBe("icp");
  });
});
