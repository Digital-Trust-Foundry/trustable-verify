"""Mints a KERI 2.0 key event log with keripy 2.0.0-dev3, from a fixed salt.

    python mint-keri-2.0.py keri-2.0-kel.json

`habbing` has no version knob in this build, so the log is built from
`eventing` directly — which is what a Hab does underneath anyway. The events
are real, signed, and framed the way the platform's KERIA frames them:
`{"v":"KERICAACAAJSON<size>."` with the size in base64 rather than hex.
"""
import json, sys
from keri.core import coring, eventing, signing

V2 = coring.Vrsn_2_0
SALT = signing.Salter(raw=b"0123456789abcdef")
DT = "2026-08-21T00:00:00.000000+00:00"


def key(path):
    return SALT.signer(path=path, temp=True)


def signed(serder, signer):
    """One event plus its controller signature attachment."""
    siger = signer.sign(serder.raw, index=0)
    return eventing.messagize(serder, sigers=[siger]).decode()


current, nxt = key("fx0"), key("fx1")

icp = eventing.incept(
    keys=[current.verfer.qb64],
    ndigs=[coring.Diger(ser=nxt.verfer.qb64b).qb64],
    isith="1", nsith="1", toad=0, wits=[], version=V2,
    code=coring.MtrDex.Blake3_256,
)
stream = signed(icp, current)
pre, dig, sn = icp.pre, icp.said, 0

# Three interactions, each anchoring a seal — the shape a registry inception
# and a credential issuance leave behind, which is what the KEL walk matches.
for anchor in ("EAAAregistryinception000000000000000000000A",
               "EAAAcredentialissuance00000000000000000000B",
               "EAAAsecondissuance0000000000000000000000000C"):
    sn += 1
    ixn = eventing.interact(
        pre=pre, dig=dig, sn=sn,
        data=[{"i": anchor, "s": "0", "d": anchor}],
        version=V2,
    )
    stream += signed(ixn, current)
    dig = ixn.said

json.dump({"issuer_aid": pre, "kel": stream}, open(sys.argv[1], "w"), indent=1)
print("issuer", pre, "| events", sn + 1, "| bytes", len(stream))
