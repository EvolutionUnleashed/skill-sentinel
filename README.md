# Skill Sentinel

**AI Agent Skill Security Scanner by Evolution Unleashed**

Skill Sentinel analyzes AI agent skills for malicious code, prompt injection, data exfiltration, and supply chain threats before they execute in your environment. Drop it into your Claude Projects, Manus, or any SKILL.md-compatible agent workspace and it automatically scans new skills against eight threat categories derived from real-world attack patterns.

## The Problem

The agent skills ecosystem has a supply chain security crisis. Research from Snyk and Cisco in early 2026 confirmed that over 13% of publicly available skills contain critical security issues, with confirmed malicious payloads designed for credential theft, backdoor installation, and data exfiltration. A single compromised skill inherits your agent's full permissions — filesystem access, environment variables, network connectivity, and credentials.

## What It Detects

Skill Sentinel scans against eight threat categories covering every confirmed attack pattern documented in the wild:

- **T1: Data Exfiltration** — Instructions that transmit sensitive data to external endpoints
- **T2: Prompt Injection** — Embedded instructions that override agent safety guidelines
- **T3: Remote Code Execution** — Download-and-execute patterns from external sources
- **T4: Credential Harvesting** — Unauthorized access to API keys, tokens, and passwords
- **T5: Obfuscated Payloads** — Base64, hex, Unicode, and other encoding used to hide malicious intent
- **T6: Privilege Escalation** — Permissions that exceed the skill's stated purpose
- **T7: Supply Chain Compromise** — Unverified external dependencies and runtime remote fetching
- **T8: Social Engineering** — Misleading descriptions and trust manipulation tactics

## How To Use It

Download the `skill-sentinel` folder and add it to your agent workspace as a skill. When you add a new skill or ask your agent to scan an existing one, Skill Sentinel activates and produces a structured Threat Assessment Report with severity ratings, evidence citations, and remediation guidance.

Works with Claude Projects, Claude Code, Manus, and any agent platform that supports SKILL.md skill files.

## Output

Every scan produces a Threat Assessment Report containing an overall risk rating (CLEAN / LOW / MEDIUM / HIGH / CRITICAL), per-category findings with exact evidence from the scanned files, and actionable remediation steps when issues are detected.

Reports also include inventory coverage and a COMPLETE / INCOMPLETE status. Unresolved
files, runtime dependencies, or inspection limits block approval and carry at least HIGH
risk. CLEAN requires complete coverage and no findings; it is not a guarantee of safety.
Compiled Python bytecode (including `__pycache__`) and other uninspectable executable
artifacts cannot be cleared by reading companion source or strings. The agent records
the gap and recommends a source-only replacement or dedicated isolated static analysis.
It never runs target code during a scan. These are agent instructions, not a runtime
enforcement mechanism. See [benign regression checks](tests/README.md).

## About Evolution Unleashed

Skill Sentinel is built by [Evolution Unleashed](https://www.evolutionunleashed.com), a 55,000+ member AI education community teaching non-technical entrepreneurs how to orchestrate AI agents. Founded by JJ (Stu Jordan), "The Agent Guy," Evolution Unleashed focuses on moving entrepreneurs from Generator to Orchestrator.

**Learn more:** [www.evolutionunleashed.com](https://www.evolutionunleashed.com)

## License

© Evolution Unleashed 2026 — All Rights Reserved

You may use this skill within your own agent workspace for personal or internal business purposes. You may not copy, redistribute, republish, sell, sublicense, or claim authorship of this skill or any derivative without explicit written permission from Evolution Unleashed. If you share or reference this skill publicly, full credit and attribution with a link to [evolutionunleashed.com](https://www.evolutionunleashed.com) is required. Modification for personal use is permitted provided the copyright notice and license remain intact.
