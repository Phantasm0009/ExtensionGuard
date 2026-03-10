# ExtensionShield

ExtensionShield is a local-first VS Code extension security scanner.

## Features
- Scan installed extensions for known malicious and vulnerable IDs.
- Run heuristic static checks for suspicious patterns.
- View a risk dashboard in the Activity Bar.
- Apply quick dashboard filters: All, Critical only, Intel matches only.
- Optionally hide or show the low-risk bucket.

## Commands
- `ExtensionShield: Scan Extensions`
- `ExtensionShield: Set Dashboard Filter`
- `ExtensionShield: Re-scan Extension`
- `ExtensionShield: Open Settings`

## Settings
- `extensionShield.showLowRiskBucket`: Show low-risk extensions in the dashboard (default: `false`).
