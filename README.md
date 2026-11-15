# Cybersecurity Use Cases & Playbooks

A collection of cybersecurity use cases designed to support the detection, investigation, and response to alerts and incidents. It includes Markdown playbooks organized by platform or finding source, a web portal for browsing them, and resources related to MITRE ATT&CK.

> **Note:** This repository is a reference resource. Use cases must be validated and adapted to your environment, telemetry sources, and organizational procedures. They do not execute response actions automatically.

## Contents

The collection includes more than 1,100 use cases across the following categories:

| Category | Use cases |
| --- | ---: |
| AWS GuardDuty | 204 |
| Cloud | 45 |
| ESXi | 8 |
| Linux | 22 |
| macOS | 13 |
| Network Devices | 100 |
| PRE | 3 |
| Windows | 718 |

Depending on the case, each use case may include a description, objective, detection logic, priority, MITRE ATT&CK mapping, investigation sources, analyst questions, false positives, and response recommendations.

## Repository structure

- [`Use Cases by Finding/`](./Use%20Cases%20by%20Finding/) — Markdown playbooks organized by finding source or platform.
- [`Mitre Attack Framework/`](./Mitre%20Attack%20Framework/) — unified MITRE ATT&CK resources in JSON and SVG formats.
- [`index.html`](./index.html) — web portal for searching and viewing use cases.

## MITRE ATT&CK coverage

The following map visualizes MITRE ATT&CK techniques mapped to the use cases:

![MITRE ATT&CK coverage map](./Mitre%20Attack%20Framework/Mitre_Attack_Framework__Unified.svg)

MITRE ATT&CK organizes adversary behavior into **tactics** and **techniques**. A tactic describes the adversary's objective (the “why”); a technique describes the method used to achieve it (the “how”). Use cases with ATT&CK identifiers can be mapped to one or more techniques and, through them, to their associated tactics. The map helps explore this coverage, but it does not imply that every tactic or technique is covered, or that a mapped technique has been detected in your environment.

Each technique is colored according to the highest severity of the use cases contributing to its mapping:

| Color | Severity |
| --- | --- |
| Purple | Critical |
| Red | High |
| Blue | Medium |
| Yellow | Low |

Severity is explicitly specified in approximately 20% of the source use cases; for the rest, it was inferred from tactics and threat-related keywords. The JSON file includes comments and metadata for each technique to distinguish explicit contributions from inferred ones. Note also that ATT&CK v19 reorganized its taxonomy: the **Defense Evasion** tactic was removed under that name and split into **Stealth** and **Defense Impairment**.

## Exploring the use cases

### Web portal

To run the portal locally, start a static web server from the repository root:

```bash
python3 -m http.server 8000
```

Then open [http://localhost:8000](http://localhost:8000). The portal retrieves the index and Markdown files from GitHub, so an Internet connection and access to the repository are required.

![Web portal](./Mitre%20Attack%20Framework/Web%20portal.png)

### Markdown files

You can also browse the folders under [`Use Cases by Finding/`](./Use%20Cases%20by%20Finding/) and open any `.md` file in a Markdown viewer or text editor.

## Use and adaptation

Before incorporating a use case into a SIEM or another platform:

1. Confirm that the detection matches your data sources and technology version.
2. Adjust the logic, thresholds, priorities, and response times to your policies.
3. Validate the investigation sources, false positives, and escalation procedures.
4. Test changes in a controlled manner and document any local modifications.

Use these materials only in environments and activities for which you have authorization.

## Contributions

All contributions are welcome! To contribute, fork the project from the `dev` branch, make your changes in your fork, and submit a pull request targeting this repository's `dev` branch.

When adding a use case, you must:

1. **Follow the structure and format** of existing use cases in the relevant category, including applicable detection and investigation sections.
2. **Place the Markdown file in the appropriate folder** under [`Use Cases by Finding/`](./Use%20Cases%20by%20Finding/), according to the platform or finding source.
3. **Map the use case to the applicable MITRE ATT&CK techniques**, using official identifiers and ensuring the mapping is supported by the use case.
4. **Update the MITRE coverage resources**: add the use case to the matrix and update [`Mitre_Attack_Framework_Unified.json`](./Mitre%20Attack%20Framework/Mitre_Attack_Framework_Unified.json) to keep the map and its data in sync.
5. **Document relevant sources, references, and assumptions** needed to validate and adapt the use case.

> **Important:** Contributions that do not meet all applicable requirements—including the required structure, correct location, and MITRE mapping and updates when adding a use case—will be rejected and will not be added to the project.

## License

See [`LICENSE`](./LICENSE) for the terms of distribution and use.
