# Proxy Import Hub

New, undeployed unified repository. Existing Surge/v2rayN repositories, deployments and links are unchanged.

The responsive administration UI provides a three-step form, a generated-link result card, copy and preview buttons, and a history list with copy/open/revoke actions. If clipboard access fails, the URL is selected for manual copying. Admin keys are not persisted to browser storage. The UI requires the deployed backend; opening the HTML file alone cannot create valid shares. This UI update does not deploy or modify existing services.

Authenticated administrators paste HTTPS subscriptions or node URIs to generate a private share page. Recipients choose Surge (macOS/iOS import schemes), Shadowrocket (best-effort add scheme with manual fallback), or v2rayN (copy subscription and paste/import in the client). No automatic clicks or client-confirmation bypasses.

## What “one-click import” means here

All three clients have entries, but **not all three have verified one-click importing**:

| Client | Current behavior | Verification limit |
|---|---|---|
| Surge, macOS / iOS | Button requests opening Surge to import a configuration | Requires installation and confirmation; the new unified portal has not passed real-device acceptance testing |
| Shadowrocket | Best-effort app-opening button, with copy-subscription fallback | Not device-tested; app/version compatibility is not guaranteed |
| v2rayN, Windows | Copy the subscription, then paste/add it in the app | This is not browser one-click import |

## For administrators

1. Deploy this project separately first. A GitHub repository URL is not a working share page. Existing Surge pages do not automatically gain the new client entries.
2. Open the deployed administration page and enter your admin key. Do not send that key to recipients.
3. Enter a recognizable name and an HTTPS subscription URL, node URIs, or a Base64 node list.
4. Generate a share page and privately send its URL to your friend. Do not share server passwords or administrator credentials.
5. Revoke the share in the administration page when no longer needed. This blocks future retrieval, not node credentials already downloaded; disable those on the node server if necessary.

## For friends receiving a link

Install your client first, then open the private share URL in a browser. Allow the browser to open the app if prompted. The page cannot install software or approve VPN permissions for you.

### Surge

Choose the macOS or iPhone import button matching your device. Allow opening Surge, confirm importing, select the configuration and enable the connection as instructed by the app. If nothing opens, verify installation and try the system browser. Unsupported source protocols may leave no usable nodes; clicking again will not fix protocol incompatibility.

### Shadowrocket

Try the import button and confirm adding the subscription if the app opens. If it fails, copy the subscription URL from the page, find the subscription-add entry in Shadowrocket, paste it, save and update. Menu names vary by version. Select a node and enable the connection. **The button remains unverified on a real device.**

### v2rayN

Copy the subscription URL, open v2rayN, focus the server list rather than a text field, and press Ctrl+V. Supporting versions interpret an HTTPS URL as a subscription. Otherwise, add it manually through subscription management, save and update the subscription. Select a node and configure the appropriate connection/system-proxy mode in the client. **Pasting is still required; do not advertise this as fully automatic browser setup.**

## Troubleshooting and privacy

- Cannot open the share: check that the new service is deployed and the share has not been revoked. A private GitHub repository is not the deployed portal.
- Imported but cannot connect: import success does not verify the server, account, quota, certificate or local network.
- Different node counts: Surge conversion can reject or omit unsupported protocols. Raw subscriptions preserve nodes, but client support still varies.
- Anyone holding a share or subscription URL can retrieve its nodes. Send privately; never publish these URLs in repositories, forums or screenshots.

Root files implement the integrated portal; apps/ contains sanitized snapshots of the two original projects. Supported source formats are node URIs and Base64 URI subscriptions, not Clash YAML. Unsupported Surge protocols cannot be converted merely by changing format. Shadowrocket integration has not been device-tested.

Deploy separately under /opt/proxy-import-hub, with private state in /var/lib/proxy-import-hub, a new environment file and user, gateway port8773, and a separate network-restricted subconverter engine on25502. Follow [deployment and security notes](README.md); never enable the original service units unchanged or replace existing default routing.

Treat share/feed URLs as secrets. Revocation blocks future retrieval but cannot revoke previously downloaded node credentials. Use separate 3x-ui clients for friends. No live credentials, state, or original server configuration are included.

Run `python -m unittest test_hub -v`. Tests cover routing, authentication, formats, encrypted storage and revocation, not real-device connectivity.
