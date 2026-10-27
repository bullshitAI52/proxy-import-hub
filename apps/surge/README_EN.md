# Surge Private Subscription

Self-hosted subscription conversion and one-click Surge import for macOS and iOS. See [deployment instructions](README.md).

Features: authenticated administration, encrypted source storage, revocable random feed URLs, native Surge import pages, local-node import, and an isolated subconverter v0.9.0 engine. No real credentials or subscription URLs are included.

Deploy to `/opt/private-sub` on Linux with Python 3.10+, systemd and an existing HTTPS reverse proxy. Install requirements and the official subconverter binary separately, create the private-sub system user and protected state/input directories, generate credentials with `setup_credentials.py`, install the supplied services, and insert only the example Nginx location block. Never replace existing default-site routing.

For 3x-ui, export compatible nodes into a private file, then run `import_nodes.py FILE --name NAME`. This imports a snapshot; it does not modify the panel, change core versions, or remove nodes. Reimport after changing credentials or ports.

Format conversion cannot make unsupported protocols compatible. VLESS/Reality may be rejected; unsupported nodes can be omitted. Both device profiles use a common supported subset. Default routing sends LAN traffic directly and other traffic through the selected proxy. There is no MITM or automatic regional routing.

Keep admin keys, source files, databases and all feed/import URLs private. Back up the encrypted database and encryption key securely. Temporary plaintext conversion files are normally removed, but crashes can leave files behind. Validate systemd network restrictions on your host. Real-device connectivity and certificate renewal remain operator responsibilities.

Tests: `python -m unittest test_server -v`. Set `SUB_TEST_ENGINE=1` and `SUB_TEST_ROOT=/var/lib/private-sub` for the optional local engine integration test.
