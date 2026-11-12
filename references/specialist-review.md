# Specialist review and provenance

Escalate when required executable content cannot be interpreted safely, dependencies
remain outside scope, or the package has access to sensitive systems. A specialist
review is a separate assessment; retain the agent scan's unresolved coverage.

Provide the artifact path and hash, package revision, intended loader/interpreter,
known permissions, observed source-to-output flow, exact coverage gaps and relevant
findings. Request a tool/version-matched assessment of the supplied compiled body,
its relationship to source and any reachable behavior. Record unsupported constructs
and parser failures. No-analysis or an unavailable analyzer is not a passing result.

Run only separately trusted, pinned analysis tools in an isolated environment. Do not
install tools, run build hooks or load deserializers supplied by the scanned package.
Do not upload private code or secrets to cloud scanners automatically. Dynamic execution
requires a separately authorized isolated workflow and is outside Sentinel's scan.

Cisco Skill Scanner documents bytecode integrity, static and semantic analyzers and is
an optional tool to evaluate. Sentinel does not bundle it, auto-install it or treat its
verdict as authoritative. Validate its current version against local regressions before
use. NVIDIA SkillSpector documents another combination of static and semantic review.

Sources consulted 12 November 2026:

- Python bytecode invalidation: https://peps.python.org/pep-0552/
- Unsafe marshal input: https://docs.python.org/3/library/marshal.html
- Cisco scanner: https://github.com/cisco-ai-defense/skill-scanner
- NVIDIA scanning: https://docs.nvidia.com/skills/scanning-agent-skills
- OWASP agent security: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- Anthropic skill review: https://platform.claude.com/docs/en/agents-and-tools/agent-skills/enterprise
- OpenAI prompt-injection design: https://openai.com/index/designing-agents-to-resist-prompt-injection/

Treat this as a dated source list, not a dependency manifest. Verify tool capabilities
when selecting a version. OWASP's Agentic Skills Top 10 was in public review when
consulted; do not describe Sentinel as certified against it.
