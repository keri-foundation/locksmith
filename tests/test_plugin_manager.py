from types import SimpleNamespace

from locksmith.plugins.manager import PluginManager


def test_on_vault_opened_extends_scheduler_with_plugin_doers():
    events = []
    plugin_doers = [object()]
    vault = SimpleNamespace(
        extend=lambda doers: events.append(("extend", doers)),
    )
    plugin = SimpleNamespace(
        plugin_id="provider",
        on_vault_opened=lambda opened_vault: events.append(("open", opened_vault)),
        get_doers=lambda: plugin_doers,
    )
    manager = PluginManager(app=None)
    manager._plugins = {plugin.plugin_id: plugin}

    manager.on_vault_opened(vault)

    assert events == [("open", vault), ("extend", plugin_doers)]


def test_get_witness_batches_merges_distinct_plugin_batches():
    manager = PluginManager(app=None)
    manager._plugins = {
        "one": SimpleNamespace(
            get_witness_batches=lambda vault, hab_pre: SimpleNamespace(
                batches=[["WIT_1", "WIT_2"], ["WIT_3"]]
            )
        ),
        "two": SimpleNamespace(
            get_witness_batches=lambda vault, hab_pre: SimpleNamespace(
                batches=[["WIT_2", "WIT_1"], ["WIT_4"]]
            )
        ),
        "three": SimpleNamespace(get_witness_batches=lambda vault, hab_pre: None),
    }

    result = manager.get_witness_batches(vault=object(), hab_pre="AID_SHARED")

    assert result is not None
    assert result.batches == [["WIT_1", "WIT_2"], ["WIT_3"], ["WIT_4"]]
