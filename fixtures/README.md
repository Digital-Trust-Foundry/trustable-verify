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
