"""Read bundled schemas without adding them to a vault."""
from PySide6.QtCore import QDir, QFile, QIODevice
from keri.core import scheming

from locksmith import resources_rc  # noqa: F401 - register bundled schemas


def builtin_schemas():
    schemas = {}
    directory = QDir(':/assets/schemas/sedi')
    for filename in directory.entryList(['*.json'], QDir.Filter.Files):
        source = QFile(directory.filePath(filename))
        if not source.open(QIODevice.OpenModeFlag.ReadOnly):
            raise OSError(source.errorString())
        try:
            schemer = scheming.Schemer(raw=bytes(source.readAll()))
        finally:
            source.close()
        schemas[schemer.said] = schemer
    return schemas


def request_schemas(vault):
    """Include imported schemas and keep one entry for each schema SAID."""
    return builtin_schemas() | {said: schemer for (said,), schemer in vault.hby.db.schema.getTopItemIter()}
