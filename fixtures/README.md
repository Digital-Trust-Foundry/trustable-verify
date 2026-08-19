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
