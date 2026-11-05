"""Receiving setup shared by identifier sharing and credential actions."""

RETRY_DELAYS = (30.0, 60.0, 120.0)
NETWORK_TIMEOUT = 30.0


def receiving_ready(vault, hab):
    """Require a usable route and completion of any provider publication."""
    from locksmith.core.ipexing import _reachable

    manager = getattr(vault, 'plugin_manager', None)
    status = manager.messaging_status(vault, hab.pre) if manager else None
    return _reachable(hab, hab.pre) and (status is None or status[0] == 'active')


async def ensure_receiving(vault, hab, *, retry=False):
    """Finish local receiving setup without changing credential consent."""
    from locksmith.core.ipexing import _reachable

    if vault.closed or hab is not vault.hby.habByPre(hab.pre):
        raise ValueError('The identifier is no longer open')
    if receiving_ready(vault, hab):
        return
    manager = getattr(vault, 'plugin_manager', None)
    if manager is None or not await manager.ensure_messaging(vault, hab.pre, retry=retry):
        raise ValueError('Complete account setup to enable messaging. Your progress is saved.')
    if vault.closed or not _reachable(hab, hab.pre):
        raise ValueError('Receiving is not ready. Open Connection details to retry.')
