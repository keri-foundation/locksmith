Developer Guide
===============

Environment
-----------

The current package metadata requires Python ``>=3.14.0``. Use Python ``3.14``
for local development and documentation work so dependency resolution matches CI
and release builds.

Setup
-----

From the repository root:

.. code-block:: bash

   python3.14 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install -e .

Qt Resource Regeneration
------------------------

The generated Qt resource module lives at ``src/locksmith/resources_rc.py``.

.. code-block:: bash

   python ./scripts/generate_qrc.py
   pyside6-rcc resources.qrc -o resources_rc.py
   mv resources_rc.py ./src/locksmith/

Running Locksmith
-----------------

Once the editable install is in place:

.. code-block:: bash

   python -m locksmith.main

Building the Docs
-----------------

Build the local HTML documentation with Sphinx:

.. code-block:: bash

   python -m pip install -r docs/requirements.txt
   sphinx-build -b html docs docs/_build/html

Plugin Lifecycle
----------------

Locksmith discovers provider integrations from the ``locksmith.plugins``
entry-point group and coordinates their UI, vault lifecycle, background work,
and optional witness hooks.

See :doc:`plugin-authoring` for the complete host contract and a walkthrough of
the bundled KERI Foundation reference implementation.
