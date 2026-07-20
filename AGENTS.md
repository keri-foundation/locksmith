# Locksmith Contributor Guidance

## Start Here

- Use Python 3.14.
- Read `docs/developer-guide.rst` before changing the application.
- For plugin work, read `docs/plugin-authoring.rst`.
- The current plugin contract is defined in:
  - `src/locksmith/plugins/base.py`
  - `src/locksmith/plugins/manager.py`
  - `src/locksmith/plugins/kerifoundation/plugin.py`

Treat the current source and tests as authoritative. Update the documentation
when a public interface changes.

## Scope

- Keep changes focused on the requested behavior.
- Do not introduce a new plugin manifest, installer, or lifecycle unless the
  task requires an architecture change.
- Keep provider-specific behavior inside the provider plugin.

## Runtime Boundaries

- Do not block the Qt and qasync event loop.
- Tie background work to one vault and one cleanup path.
- Use the HIO scheduler API when adding doers after startup.
- Keep widgets, service clients, and persistent state separate.
- Use Keripy to construct and parse KERI and CESR messages.
- Keep wallet state, plugin state, and remote service state separate.

## Generated Files

Do not edit `src/locksmith/resources_rc.py` directly. Regenerate it from
`resources.qrc` and the assets.

Do not commit local vault data, credentials, environment files, or generated
documentation.

## Verification

Run focused tests for code changes. Build Sphinx for documentation changes.
State any checks that you could not run.
