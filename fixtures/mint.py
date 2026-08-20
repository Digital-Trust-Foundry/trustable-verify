"""Mints the approval fixtures with keripy 2.0.0-dev3 — the version the platform
pins — from a fixed salt, so a rerun reproduces the same bytes.

    python mint.py approved.json approvals-rejected.json

A genesis credential requiring two named signers, the two approval credentials
that answer it, and two more that must not count: one approving a different
Trustable, one whose issuance no key log seals.
"""
import json, sys
from keri.app import habbing
from keri.core import coring, signing
from keri.vdr import eventing as veventing
from keri.vc import proving

SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
ROUND = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
DT = "2026-08-20T20:00:00.000000+00:00"

def kel(hab):
    out = b""
    sn = 0
    while True:
        try:
            out += hab.makeOwnEvent(sn=sn)
        except Exception:
            break
        sn += 1
    return out.decode()

def registry(hab, nonce):
    vcp = veventing.incept(hab.pre, baks=[], toad=0, nonce=nonce,
                           cnfg=[veventing.TraitDex.NoBackers])
    hab.interact(data=[dict(i=vcp.pre, s="0", d=vcp.said)])
    return vcp

def issue(hab, regk, said):
    iss = veventing.issue(vcdig=said, regk=regk, dt=DT)
    hab.interact(data=[dict(i=said, s="0", d=iss.said)])
    return iss

def tel_pkg(said, iss):
    return {"said": said, "status": "issued", "tel_event_count": 1,
            "tel_events": [{"event_type": "iss", "said": iss.said, "sn": "0",
                            "timestamp": DT, "event": iss.raw.decode()}]}

def reg_pkg(vcp):
    return {"tel_events": [{"event_type": "vcp", "said": vcp.said, "sn": "0",
                            "timestamp": "", "event": vcp.raw.decode()}]}

with habbing.openHby(name="fx", base="", temp=True,
                     salt=signing.Salter(raw=b"0123456789abcdef").qb64) as hby:
    issuer = hby.makeHab(name="issuer", icount=1, isith="1", ncount=1,
                         nsith="1", toad=0, wits=[])
    alice = hby.makeHab(name="alice", icount=1, isith="1", ncount=1,
                        nsith="1", toad=0, wits=[])
    bob = hby.makeHab(name="bob", icount=1, isith="1", ncount=1,
                      nsith="1", toad=0, wits=[])
    carol = hby.makeHab(name="carol", icount=1, isith="1", ncount=1,
                        nsith="1", toad=0, wits=[])
    dave = hby.makeHab(name="dave", icount=1, isith="1", ncount=1,
                       nsith="1", toad=0, wits=[])

    ireg = registry(issuer, "0AA90Ihcwnh7CqbOHMLOmwfz")
    genesis = proving.credential(
        schema=SCHEMA, issuer=issuer.pre, status=ireg.pre,
        data={
            "dt": DT,
            "content_hash": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "signature_policy": {
                "threshold": 2,
                "required_roles": [],
                "candidates": [
                    {"actor_aid": alice.pre, "role": "officer"},
                    {"actor_aid": bob.pre, "role": "officer"},
                ],
            },
        },
    )
    giss = issue(issuer, ireg.pre, genesis.said)

    approvals = []
    for hab, name in ((alice, "alice"), (bob, "bob")):
        reg = registry(hab, "0AA90Ihcwnh7CqbOHMLOmwf" + name[0].upper())
        cred = proving.credential(
            schema=SCHEMA, issuer=hab.pre, status=reg.pre,
            data={"dt": DT, "trustable_said": genesis.said,
                  "signer_aid": hab.pre, "round_id": ROUND,
                  "lifecycle": {"event": "issue", "state": "issued"}},
            source={"d": "", "genesis": {"n": genesis.said, "s": SCHEMA}},
        )
        iss = issue(hab, reg.pre, cred.said)
        approvals.append({
            "acdc_said": cred.said, "issuer_aid": hab.pre,
            "registry_id": reg.pre, "cesr": cred.raw.decode(),
            "kel": kel(hab), "tel": tel_pkg(cred.said, iss),
            "registry_tel": reg_pkg(reg),
        })

    # Two approvals that must NOT count. Both are real credentials, correctly
    # signed and correctly framed — what disqualifies them is what they say and
    # what their signer's log does not.
    other = proving.credential(
        schema=SCHEMA, issuer=issuer.pre, status=ireg.pre,
        data={"dt": DT, "content_hash": "sha256:other"},
    )
    issue(issuer, ireg.pre, other.said)

    rejected = []
    # Carol approves a different credential entirely.
    creg = registry(carol, "0AA90Ihcwnh7CqbOHMLOmwfC")
    ccred = proving.credential(
        schema=SCHEMA, issuer=carol.pre, status=creg.pre,
        data={"dt": DT, "trustable_said": other.said, "signer_aid": carol.pre,
              "round_id": ROUND, "lifecycle": {"event": "issue", "state": "issued"}},
        source={"d": "", "genesis": {"n": other.said, "s": SCHEMA}},
    )
    ciss = issue(carol, creg.pre, ccred.said)
    rejected.append({"acdc_said": ccred.said, "issuer_aid": carol.pre,
                     "registry_id": creg.pre, "cesr": ccred.raw.decode(),
                     "kel": kel(carol), "tel": tel_pkg(ccred.said, ciss),
                     "registry_tel": reg_pkg(creg)})

    # Dave approves this credential, but nothing in his key log seals it.
    dreg = registry(dave, "0AA90Ihcwnh7CqbOHMLOmwfD")
    dcred = proving.credential(
        schema=SCHEMA, issuer=dave.pre, status=dreg.pre,
        data={"dt": DT, "trustable_said": genesis.said, "signer_aid": dave.pre,
              "round_id": ROUND, "lifecycle": {"event": "issue", "state": "issued"}},
        source={"d": "", "genesis": {"n": genesis.said, "s": SCHEMA}},
    )
    diss = veventing.issue(vcdig=dcred.said, regk=dreg.pre, dt=DT)
    rejected.append({"acdc_said": dcred.said, "issuer_aid": dave.pre,
                     "registry_id": dreg.pre, "cesr": dcred.raw.decode(),
                     "kel": kel(dave), "tel": tel_pkg(dcred.said, diss),
                     "registry_tel": reg_pkg(dreg)})

    base = "https://platform.example.invalid"
    pkg = {
        "schema_version": 1,
        "trustable_said": genesis.said,
        "acdc_said": genesis.said,
        "issuer_aid": issuer.pre,
        "registry_id": ireg.pre,
        "foundry_base_url": base,
        "foundry_tenant_id": "00000000-0000-0000-0000-000000000000",
        "cesr": genesis.raw.decode(),
        "acdc": json.loads(genesis.raw.decode()),
        "integrity": {"said_checkable": True},
        "kel": kel(issuer),
        "packaged_at": "2026-08-19T00:00:00.000Z",
        "discovery": {
            "kel": f"{base}/.well-known/keri/kel/AID/cesr",
            "tel": f"{base}/.well-known/keri/tel/SAID",
            "status": f"{base}/.well-known/keri/tel/SAID",
        },
        "tel": tel_pkg(genesis.said, giss),
        "registry_tel": reg_pkg(ireg),
        "approvals": approvals,
        "credential_status": {"status": "issued", "said": genesis.said,
                              "as_of": "2026-08-19T00:00:00.000Z"},
    }
    json.dump(pkg, open(sys.argv[1], "w"), indent=1)
    json.dump({**pkg, "approvals": rejected}, open(sys.argv[2], "w"), indent=1)
    print("genesis", genesis.said, "alice", alice.pre, "bob", bob.pre,
          "carol", carol.pre, "dave", dave.pre)
