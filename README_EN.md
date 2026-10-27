# Proxy Import Hub

New, undeployed unified repository. Existing Surge/v2rayN repositories, deployments and links are unchanged.

Authenticated administrators paste HTTPS subscriptions or node URIs to generate a private share page. Recipients choose Surge (macOS/iOS import schemes), Shadowrocket (best-effort add scheme with manual fallback), or v2rayN (copy subscription and paste/import in the client). No automatic clicks or client-confirmation bypasses.

Root files implement the integrated portal; apps/ contains sanitized snapshots of the two original projects. Supported source formats are node URIs and Base64 URI subscriptions, not Clash YAML. Unsupported Surge protocols cannot be converted merely by changing format. Shadowrocket integration has not been device-tested.

Deploy separately under /opt/proxy-import-hub, with private state in /var/lib/proxy-import-hub, a new environment file and user, gateway port8773, and a separate network-restricted subconverter engine on25502. Follow [deployment and security notes](README.md); never enable the original service units unchanged or replace existing default routing.

Treat share/feed URLs as secrets. Revocation blocks future retrieval but cannot revoke previously downloaded node credentials. Use separate 3x-ui clients for friends. No live credentials, state, or original server configuration are included.

Run `python -m unittest test_hub -v`. Tests cover routing, authentication, formats, encrypted storage and revocation, not real-device connectivity.
