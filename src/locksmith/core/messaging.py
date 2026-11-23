"""Receiving setup shared by identifier sharing and credential actions."""

from keri import kering


RETRY_DELAYS = (30.0, 60.0, 120.0)
NETWORK_TIMEOUT = 30.0


def delivery_route(hab, pre):
    """Return the first authorized role with endpoints that can receive an HTTP stream."""
    ends = hab.endsFor(pre)
    for role in (kering.Roles.controller, kering.Roles.agent, kering.Roles.mailbox):
        endpoints = {}
        for eid, urls in ends.get(role, {}).items():
            locations = {scheme: url for scheme, url in urls.items()
                         if scheme in (kering.Schemes.http, kering.Schemes.https) and url}
            if locations:
                endpoints[eid] = locations
        if endpoints:
            return role, endpoints
    return None


def unpublished_mailboxes(vault, pre):
    """Return mailbox EIDs to omit from this identifier's introductions."""
    manager = getattr(vault, 'plugin_manager', None)
    return manager.unpublished_mailboxes(vault, pre) if manager else set()


def receiving_ready(vault, hab):
    """Require a usable route and completion of any provider publication."""
    manager = getattr(vault, 'plugin_manager', None)
    status = manager.messaging_status(vault, hab.pre) if manager else None
    return delivery_route(hab, hab.pre) is not None and (status is None or status[0] == 'active')


async def ensure_receiving(vault, hab, *, retry=False):
    """Finish local receiving setup without changing credential consent."""
    if vault.closed or hab is not vault.hby.habByPre(hab.pre):
        raise ValueError('The identifier is no longer open')
    if receiving_ready(vault, hab):
        return
    manager = getattr(vault, 'plugin_manager', None)
    if manager is None or not await manager.ensure_messaging(vault, hab.pre, retry=retry):
        raise ValueError('Complete account setup to enable messaging. Your progress is saved.')
    if vault.closed or not receiving_ready(vault, hab):
        raise ValueError('Receiving is not ready. Open Connection details to retry.')
