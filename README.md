# Skill Sentinel

**AI agent skill security review by Evolution Unleashed**

Skill Sentinel reviews unfamiliar skills before use and gives the owner an evidence-backed
installation decision. It combines an agent's contextual review with an optional small,
standard-library helper that checks inventory, package identity and verdict consistency.

## What you get

- A decision: **PROCEED**, **REVIEW** or **BLOCK**, with the next action.
- Separate scan coverage and observed threat severity, so unknown contents are not called malware.
- Evidence against eight categories: exfiltration, injection, unsafe execution, credential exposure,
  hidden behavior, excessive authority, supply-chain risk and deception.
- The package's read/write paths, network destinations, execution capabilities and unresolved dependencies.

Python bytecode, disguised executables and other unverified artifacts block approval.
Harmless companion source cannot clear compiled code. Target code is never executed
as part of a scan. A CLEAN result means no findings within a complete review of those
bytes; it does not guarantee safety or cover later changes.

## Use it

Add the trusted Sentinel folder to an agent workspace that supports SKILL.md skills,
then ask it to review a separate target skill before installation. Prompt-only hosts use
**ADVISORY** mode. The methodology works without installing packages or external scanners.

For **GATED** mode, use the trusted `scripts/preflight.py` with Python 3.10+ on a POSIX
host and a frozen local target. The agent follows [the assessment contract](references/assessment-format.md):

1. Inventory and fingerprint the supplied package.
2. Review its readable content and record coverage, findings and capabilities.
3. Re-inventory and validate the assessment; consume the helper's derived decision.

The helper enforces fixed conservative limits and never trusts a model to remove its
blockers. It blocks opaque assets, containers and all links; use a source-only package
or a separate specialist assessment when necessary. Windows and restricted hosts retain
advisory review. The helper cannot prove that a model understood the content or enforce
the host's runtime permissions. It detects observed changes; a frozen snapshot and an
installation-time identity check are still required.

The existing overall rating remains for compatibility: incomplete coverage carries at
least HIGH, while actual findings are shown separately. **Use the decision field** for
installation gating. Never interpret “no observed threats” as approval for an incomplete scan.

## Validation

Run the trusted tests from this repository:

```sh
python3 -I -B tests/regression.py
python3 -I -B tests/test_preflight.py
python3 -I -B tests/test_evaluation.py
```

[Benign regression fixtures](tests/README.md) exercise compiled formats and controls.
[The evaluation procedure](references/evaluation.md) records false alarms, missed threats,
unsupported CLEAN results and unsafe scan actions across hosts/models. Automated helper
tests and model evaluations are reported separately. No reporter payload is required.

## Research and limits

A February 2026 Snyk study found critical issues in 13.4% of its 3,984-skill sample.
That is a dated sample, not a current prevalence claim for every registry.
[Research source](https://research.snyk.io/blog/agent-skills-threat-landscape/).

Current [specialist-review guidance](references/specialist-review.md) documents the
boundary between agent reasoning, dedicated static analysis and runtime enforcement.
Sentinel cannot guarantee detection of every attack. Least privilege, isolation and
appropriate human approval remain responsibilities of the agent host.

## About Evolution Unleashed

Created by JJ (Stu Jordan), Evolution Unleashed helps entrepreneurs put AI agents and
repeatable systems to work. [Evolution Unleashed](https://www.evolutionunleashed.com).

## License

© Evolution Unleashed 2026 — All Rights Reserved

You may use this skill within your own agent workspace for personal or internal business purposes. You may not copy, redistribute, republish, sell, sublicense, or claim authorship of this skill or any derivative without explicit written permission from Evolution Unleashed. If you share or reference this skill publicly, full credit and attribution with a link to [evolutionunleashed.com](https://www.evolutionunleashed.com) is required. Modification for personal use is permitted provided the copyright notice and license remain intact.
