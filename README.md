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
