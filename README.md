# @dtfoundry/trustable-verify

Verify a Trustable from its portable verify package, with no network access of
any kind.

A Trustable is normally checked by asking the Platform that minted it. That
works while both sides share a deployment and the minting tenant is known. It
does not work for a counterparty in another organisation, an auditor reading an
archive years later, or anyone on a machine with no route out.

The verify package is the evidence made portable: the credential, the issuer's
signed key event log, and the registry's history of that credential, exported as
one document and archived beside the business artifact it attests. This library
is the checker for it.

```bash
npm install @dtfoundry/trustable-verify
```

```ts
import { readFileSync } from "node:fs";
import { verifyPackage } from "@dtfoundry/trustable-verify";

const pkg = JSON.parse(readFileSync("contract.keri.json", "utf8"));
const result = verifyPackage(pkg);

result.isValid;                  // false unless every check below holds
result.status;                   // verified | revoked | suspended | invalid
result.authenticity.established; // was the issuer's authorship proven
result.as_of;                    // the moment this answer is about
```

## What it checks

**Integrity.** The credential's identifier is recomputed over its own bytes. A
self-addressing identifier is a digest of the field that carries it, so the
field is replaced by a dummy of its own length before hashing — which means the
answer cannot be reproduced from a database projection, and any byte changed
anywhere breaks it.

**Authorship.** This is the part that matters, and it does not work the way
people expect. There is no signature on the credential to check. What binds a
credential to its issuer is a chain:

1. the credential's bytes hash to the identifier it claims;
2. the registry's issuance event names that credential and hashes to its own
   identifier;
3. that identifier appears in a seal inside an event in the issuer's key event
   log;
4. that key event is signed by the keys that were in force when it was written,
   established by walking the log from its inception through every rotation.

Registry events carry no signatures of their own. Break step 3 and anyone could
mint an issuance for a credential they do not control — which is exactly what
`fixtures/unanchored-issuance.json` is, and the suite proves it is rejected.

**Revocation.** Read from the last *anchored* registry event. An event the
issuer never sealed does not get to say whether a credential stands.

## What it does not check

**Witness receipts.** They travel in the key event log and are parsed past. A
witness threshold is a different trust question, and no relying party is
currently asking it of an archived package.

**Schema compliance.** Reported as `degraded`. Carrying the schema document is
what makes the check possible later; it is not the check.

**Whether the credential is valid *now*.** It cannot be, and that is the whole
point of `as_of`. An offline answer describes the moment the package was made.
A credential revoked after that will still read as issued here, because the
evidence of the revocation is not in the file. **Offline means valid as of
package time, not currently valid.** Where a live check is possible, make one.

## Honest failure

`isValid` is true only when authorship was *proven*, not merely
un-contradicted. Recomputing an identifier shows a credential hashes to itself,
which anyone can arrange for a credential they minted — so a package whose key
log is missing or unverifiable comes back `isValid: false` with the reason
stated, rather than a "verified" that would mean only that the file is
self-consistent.

The report shares its shape with the Platform's hosted verification, so a
consumer does not learn a second vocabulary to read an offline answer.

## Fixtures

`fixtures/` holds real packages minted with keripy against a throwaway
identifier. They are checked in on purpose: a verifier whose tests build their
own inputs proves only that it agrees with itself.

## Compatibility

Implements package `schema_version: 1`. A package declaring anything else is
refused rather than interpreted. Node 20+; no runtime dependency beyond
`@noble/hashes` and `@noble/curves`, and nothing platform-specific — it runs in
a browser as readily as on a server.

## Licence

Apache-2.0.
