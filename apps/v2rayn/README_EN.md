# v2rayN Private Import

Standalone, standard-library Python portal for copying node links and serving Base64 subscriptions. Follow [deployment instructions](README.md).

Click Copy Nodes, then use Ctrl+V on the v2rayN server list or its clipboard-import command. Alternatively add the HTTPS subscription URL and update it. This does not claim automatic browser-to-app installation.

The exporter reads explicit enabled VMess TCP/WS TLS inbounds from 3x-ui without modifying the panel, upgrading/downgrading its core, deleting clients, or changing ports. Exported data is a snapshot; update after changing credentials. Rotate the portal token to revoke access links.

Deploy as an unprivileged service on localhost behind an existing HTTPS proxy. Only add the provided location; preserve default virtual hosts. State contains plaintext node credentials and must remain mode600 in a mode700 directory, outside Git. Encrypt backups. Revocation cannot remove credentials already downloaded by clients.

Tests: `python3 -m unittest test_portal -v`. Actual client connectivity, certificates and firewall access require separate verification.
