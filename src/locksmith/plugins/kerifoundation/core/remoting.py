# -*- encoding: utf-8 -*-
"""
locksmith.plugins.kerifoundation.core.remoting module

HTTP clients for provisioning and registering controller AIDs with
KERI Foundation witnesses.
"""
import asyncio
from urllib.parse import urljoin

from locksmith.core.tasking import await_owned_result

import requests
from keri import help, kering
from keri.core import coring
from keri.app.httping import CESR_DESTINATION_HEADER

logger = help.ogler.getLogger(__name__)


def provision_witness(hab_pre, boot_url):
    """Provision a witness for a controller AID via POST /witnesses."""
    url = urljoin(boot_url, "/witnesses")
    logger.info(f"Provisioning {hab_pre[:12]}... via {url}")

    response = requests.post(
        url,
        json={"aid": hab_pre},
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    eid = data.get("eid", "")
    oobis = data.get("oobis") or []
    oobi = oobis[0] if oobis else ""

    if not eid:
        raise ValueError(f"Witness response missing 'eid' field: {data}")
    if not oobi:
        raise ValueError(f"Witness response missing 'oobis' field: {data}")

    logger.info(f"Provisioned witness {eid[:12]}... for {hab_pre[:12]}...")

    return {"eid": eid, "oobi": oobi}


def _witness_registration_fields(hab, witness_eid, secret):
    kel = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre, gvrsn=kering.Version):
        kel.extend(msg)
    fargs = {"kel": kel.decode("utf-8")}

    # Include shared secret for batch mode
    if secret is not None:
        fargs["secret"] = secret

    # Include delegator KEL if identifier is delegated
    if hab.kever.delegated:
        delkel = bytearray()
        for msg in hab.db.cloneDelegation(hab.kever, gvrsn=kering.Version):
            delkel.extend(msg)
        fargs["delkel"] = delkel.decode("utf-8")

    headers = {CESR_DESTINATION_HEADER: witness_eid}

    return fargs, headers


def _request_witness_registration(witness_eid, witness_url, fargs, headers):
    response = requests.post(
        urljoin(witness_url, "/aids"), files={k: (None, v) for k, v in fargs.items()},
        headers=headers, timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _witness_registration_result(hab, witness_eid, data):
    if "totp" not in data:
        raise ValueError(f"Witness response missing 'totp' field: {data}")

    # Decrypt TOTP seed: encrypted with controller's public key
    m = coring.Matter(qb64=data["totp"])
    d = coring.Matter(qb64=hab.decrypt(ser=m.raw))
    seed = d.raw.decode("utf-8")

    logger.info(f"Successfully registered with witness {witness_eid[:12]}...")

    return {
        "totp_seed": seed,
        "oobi": data.get("oobi", ""),
        "eid": witness_eid,
    }

def register_with_witness(hab, witness_eid, witness_url, secret=None):
    """Synchronous registration for callers that own the identifier's thread."""
    fargs, headers = _witness_registration_fields(hab, witness_eid, secret)
    data = _request_witness_registration(witness_eid, witness_url, fargs, headers)
    return _witness_registration_result(hab, witness_eid, data)


async def register_with_witness_async(hab, witness_eid, witness_url, secret=None, *, vault=None):
    """Export/decrypt on the vault loop and run only multipart HTTP in a worker."""
    if vault is not None and getattr(vault, "closed", False):
        raise asyncio.CancelledError
    fargs, headers = _witness_registration_fields(hab, witness_eid, secret)
    data = await await_owned_result(asyncio.to_thread(
        _request_witness_registration, witness_eid, witness_url, fargs, headers,
    ))
    if vault is not None and getattr(vault, "closed", False):
        raise asyncio.CancelledError
    return _witness_registration_result(hab, witness_eid, data)


def deprovision_witness(eid: str, boot_url: str) -> bool:
    """Best-effort DELETE /witnesses/{eid} on the boot server.

    Returns ``True`` on a successful (2xx) response, ``False`` on any
    error.  Never raises — failures are logged as warnings.

    Note: witness-hk may return 500 for an unknown *eid* because
    ``deleteWitness`` raises ``ValueError`` which the HTTP handler does
    not catch as a ``ConfigurationError``.  This is a known gap.
    """
    url = urljoin(boot_url, f"/witnesses/{eid}")
    logger.info(f"Deprovisioning witness {eid[:12]}... via DELETE {url}")

    try:
        response = requests.delete(url, timeout=15)
        response.raise_for_status()
        logger.info(f"Deprovisioned witness {eid[:12]}...")
        return True
    except Exception:
        logger.warning(f"Failed to deprovision witness {eid[:12]}... at {url}", exc_info=True)
        return False
