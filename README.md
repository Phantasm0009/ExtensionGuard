# ExtensionShield

ExtensionShield is a local-first VS Code extension security scanner.

## Features
- Scan installed extensions for known malicious and vulnerable IDs.
- Run heuristic static checks for suspicious patterns.
- View a risk dashboard in the Activity Bar.
- Apply quick dashboard filters: All, Critical only, Intel matches only.
- Optionally hide or show the low-risk bucket.
- Detect typosquat-like publisher/name impersonation patterns.
- Trust specific extensions to suppress heuristic noise while keeping intel matches.
- Export the latest scan report as JSON or Markdown.
- Optional automatic re-scan when extensions change.

## Threat Intel Sources
- Microsoft VS Marketplace removed packages history (exact extension IDs and removal categories):
	`https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md`
- CVE references (example: Live Server):
	`https://nvd.nist.gov/vuln/detail/CVE-2025-65717`
- Campaign IOC context (host indicators):
	`https://www.bleepingcomputer.com/news/security/malicious-vscode-extensions-infect-windows-with-cryptominers/`

## Commands
- `ExtensionShield: Scan Extensions`
- `ExtensionShield: Refresh Intel Now`
- `ExtensionShield: Set Dashboard Filter`
- `ExtensionShield: Re-scan Extension`
- `ExtensionShield: Toggle Trusted Extension`
- `ExtensionShield: Export Last Report`
- `ExtensionShield: Open Settings`

## Settings
- `extensionShield.showLowRiskBucket`: Show low-risk extensions in the dashboard (default: `false`).
- `extensionShield.trustedExtensions`: Suppress heuristics for selected extension IDs.
- `extensionShield.scanOnExtensionChange`: Automatically scan when installed extensions change.
- `extensionShield.enableNetworkIntelUpdates`: Opt-in remote intel updates.
- `extensionShield.intelUpdateUrl`: Endpoint for remote threat intel JSON.
