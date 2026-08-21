"""Mints a KERI 2.0 ACDC — the shape KERIA hands a wallet to sign.

    uv run --with keri==2.0.0-dev3 mint-acdc-2.0.py acdc-2.0-approval.json

An officer's approval, chained by an `e.genesis` edge to the credential it
approves, and framed `{"v":"ACDCCAACAAJSON<size>."` with the size in base64
rather than the six hex digits 1.0 used. The platform's `prepare_acdc` builds
exactly this: `versify(proto=acdc, pvrsn=Vrsn_2_0)`, then `SerderACDC(makify=
True)` to compute the SAID over the whole envelope, edge included.

Two credentials come out of one run, and the pair is the point: the same
issuance minted 1.0 and 2.0, so a test can show one parser reading both rather
than a parser that happens to agree with whichever it was written against.
"""
import json, sys
from keri.core import coring, serdering
from keri.kering import versify, Protocols, Vrsn_1_0, Vrsn_2_0, Kinds

SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
ISSUER = "EEN4xFv7M1j72wgWfKyg3-yAjN98DWVwSaxF7qaD62Ch"
REGISTRY = "EL_rbzQoDD6q78NgbZ-HroweNfEVBdIU-1YTd64cZCwa"
GENESIS = "EEUTj_BhT1U3HJYvQlRi5OjHImrVMPKrRswchUpb8MSq"
DT = "2026-08-21T00:00:00.000000+00:00"

ATTRIBUTES = {
    "dt": DT,
    "content": {"document_hash": "sha256:" + "a" * 64},
    "signer_aid": ISSUER,
    "content_type": "enterprise_signed_document",
    "trustable_said": "EAAAtrustable000000000000000000000000000000",
}
EDGE = {"d": "", "genesis": {"n": GENESIS, "s": SCHEMA}}


def mint(version, registry_field):
    """One credential, framed at the version asked for."""
    sad = {
        "v": versify(proto=Protocols.acdc, pvrsn=version, kind=Kinds.json, size=0),
        "d": "",
        "i": ISSUER,
        registry_field: REGISTRY,
        "s": SCHEMA,
        "a": dict(ATTRIBUTES),
        "e": dict(EDGE),
    }
    return serdering.SerderACDC(sad=sad, makify=True)


two, one = mint(Vrsn_2_0, "rd"), mint(Vrsn_1_0, "ri")
out = sys.argv[1] if len(sys.argv) > 1 else "acdc-2.0-approval.json"
with open(out, "w") as handle:
    json.dump(
        {
            "genesis_said": GENESIS,
            "issuer_aid": ISSUER,
            "v2": {"said": two.said, "cesr": two.raw.decode()},
            "v1": {"said": one.said, "cesr": one.raw.decode()},
        },
        handle,
        indent=2,
    )
    handle.write("\n")
print(f"{out}: 2.0 {two.said}  1.0 {one.said}")
