"""Complete receiving setup before a user-approved wallet action."""

import asyncio

from locksmith.core.messaging import ensure_receiving, receiving_ready


def prepare_messaging(widget, app, hab, resume, show_error):
    """Return True while setup owns the dialog; resume only while it remains open."""
    if receiving_ready(app.vault, hab):
        return False
    if getattr(widget, '_messaging_task', None) is not None:
        return True
    vault = app.vault
    loop = asyncio.get_running_loop()

    async def prepare():
        try:
            await ensure_receiving(vault, hab)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            show_error(str(exc))
            if not getattr(widget, '_connection_button', None):
                from locksmith.ui.toolkit.widgets import LocksmithInvertedButton
                def details():
                    from locksmith.ui.vault.identifiers.view import ViewIdentifierDialog
                    dialog = ViewIdentifierDialog(':/assets/custom/identifiers.png', app, hab.name, widget)
                    dialog.open()
                widget._connection_button = LocksmithInvertedButton('Connection details')
                widget._connection_button.clicked.connect(details)
                widget.content_layout.addWidget(widget._connection_button)
            return
        finally:
            widget._messaging_task = None
            widget.finished.disconnect(cancel)
            widget.content_layout.parentWidget().setEnabled(True)
        if app.vault is vault and not vault.closed:
            resume()

    def cancel(*_):
        task = widget._messaging_task
        if task is not None:
            task.cancel()

    widget.content_layout.parentWidget().setEnabled(False)
    widget.finished.connect(cancel)
    widget._messaging_task = loop.create_task(prepare())
    return True
