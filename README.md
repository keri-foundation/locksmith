# Locksmith

This is the KERI Foundation open port of the Locksmith wallet.

Install Python 3.14 and [uv 0.9.18](https://docs.astral.sh/uv/getting-started/installation/).
From the repository root:

```bash
uv sync --locked
uv run --locked python -m locksmith.main
```

See the [developer guide](docs/developer-guide.rst) for tests, dependency updates,
and asset generation.

Use the checked-in lockfile to install the pinned keripy source and its matching
dependencies. KF account onboarding works with Boot services that do not offer
mailboxes. Mailbox setup starts only when Boot advertises it in bootstrap config;
see the [KF plugin guide](docs/kerifoundation-plugin.rst) for provider configuration.

To send a credential between two wallets, follow the
[credential exchange guide](docs/credential-exchange.rst).

## To run with local witness, watchers

### in witness-hk

```
witopnet marshal start \
  --config-dir ./scripts \
  --host 0.0.0.0 \
  --http 5632 \
  --boothost 127.0.0.1 \
  --bootport 5631
```

### in watcher-hk

```
watopnet marshal start \
  --config-dir ./scripts \
  --host 0.0.0.0 \
  --http 7632 \
  --boothost 127.0.0.1 \
  --bootport 7631
```

### in locksmith

```
uv run --locked python -m locksmith.main
```

KERI Foundation plugin documentation lives in
[`docs/kerifoundation-plugin.rst`](docs/kerifoundation-plugin.rst).

Third-party plugin authors should start with
[`docs/plugin-authoring.rst`](docs/plugin-authoring.rst).
