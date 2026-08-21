# Fixtures

Real packages, minted with keripy against a throwaway identifier that exists
nowhere but this directory. No tenant, no customer, no document — the credential
attests a hash of the letter `a`.

They are checked in deliberately. A verifier whose tests build their own inputs
proves only that it agrees with itself; these are the bytes the system actually
produces, frozen at package schema version 1, and a change that breaks them is a
compatibility break for anyone who archived a package.

- `issued.json` — a sealed credential, its registry inception and issuance both
  anchored in the issuer's signed key event log.
- `revoked.json` — the same credential after a revocation, likewise anchored.

- `multisig.json` — a credential naming a threshold of three, which cannot reach
  a verified verdict because a package carries no approval credentials.
- `legacy-no-policy.json` — a credential from before the signature policy was
  bound into the envelope. Not editable into existence: removing the field from
  a package breaks its identifier, which is what binding it was for.

- `approved.json` — a credential requiring two named signers, carrying both
  approval credentials with the evidence that proves them: each signer's own key
  event log and the registry history anchoring their approval's issuance. This
  is the case the product is built around, and it verifies.
- `approvals-rejected.json` — the same credential, with two approvals that must
  not count. Both are genuine, correctly signed credentials; one approves a
  different Trustable, and the other's issuance is sealed into nobody's key log.

- `keri-2.0-kel.json` — a key event log framed the KERI 2.0 way, which is what
  the platform's KERIA actually emits: `{"v":"KERICAACAAJSON<size>."`, with the
  size in base64 and the string closed by `.` rather than `_`. Every other
  fixture here is 1.0, and while they were the only ones a stream carrying 2.0
  events parsed as empty — the verifier reported that the issuer had no key
  state rather than that it could not read one. An inception and three
  interactions, each anchoring a seal, which is the shape a registry inception
  and a credential issuance leave behind.

`mint.py` produces `approved.json` and `approvals-rejected.json` from a fixed
salt, so a rerun reproduces the same bytes. `mint-keri-2.0.py` does the same for
`keri-2.0-kel.json`; it builds its events from `keri.core.eventing` directly
because `habbing` in this keripy build has no version knob, which is what a Hab
does underneath in any case. It needs keripy 2.0.0-dev3 — the
version the platform pins — and is here so the fixtures can be regenerated
rather than hand-edited, which is the one thing that would quietly turn them
into the verifier agreeing with itself.
