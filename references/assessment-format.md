# Deterministic assessment contract (v2)

The optional helper requires Python 3.10+ and POSIX descriptor/no-follow support.
Prompt-only hosts keep advisory review. Use a trusted Sentinel installation outside the
target, a frozen local package, and a trusted output directory outside that package.
The helper never reads configuration or policy from the target.

```sh
python3 -I -B /trusted/skill-sentinel/scripts/preflight.py inventory /review/package > /trusted/review/manifest.json
```

Exit 0 means the inventory found no mechanical blockers. Exit 2 means blockers exist;
keep that manifest and continue useful review, but withhold approval. Do not install a
package based only on inventory. Do not use shell `&&` to silently drop the report when
inventory exits 2. The helper emits JSON on stdout and does not write to the target.

Fixed limits: 2,000 entries, 1 MiB per regular file, 16 MiB total reads, directory depth
16, cooperative 15-second budget. Outer filesystem/process timeout belongs to the host.
Limits cannot be supplied by the model. Any limit breach blocks. Do not place the
manifest, assessment or result inside the package. Scan an exported distribution;
`.git` and other ignored entries are included if supplied.

## Agent assessment

Read all candidate text and apply every threat category. Build this exact JSON shape,
with no extra keys. Replace example strings with actual evidence. Arrays may be empty
when there is nothing to report; required fields must still be present.

```json
{
  "schema_version": 2,
  "snapshot_id": "copy from the trusted manifest",
  "coverage": "COMPLETE",
  "executed_target": false,
  "categories_reviewed": ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8"],
  "reviewed_files": [
    {"path": "SKILL.md", "sha256": "copy its hash after reviewing these bytes"}
  ],
  "findings": [],
  "unresolved": [],
  "capabilities": {"reads": [], "writes": [], "network": [], "executes": []},
  "dependencies": []
}
```

`reviewed_files` must contain each manifest entry of kind `text` exactly once, matching
its path and SHA-256. It cannot turn an unresolved binary into reviewed source. Missing
or extra paths, duplicate paths and hash mismatches block. `executed_target` must be the
JSON boolean false, not 0 or a string. This assertion needs independent trace review;
the helper cannot observe the agent's actions.

Each finding has exactly these nonempty string fields:

```json
{
  "category": "T2",
  "severity": "HIGH",
  "confidence": "HIGH",
  "path": "SKILL.md",
  "evidence": "redacted source evidence",
  "reason": "the concrete authority boundary being crossed",
  "recommendation": "the action needed to remediate"
}
```

Category is T1–T8. Severity is LOW/MEDIUM/HIGH/CRITICAL; confidence LOW/MEDIUM/HIGH.
Use `unresolved` entries shaped as `{"path":"relative path","reason":"gap"}`.
Do not manufacture a threat finding for a binary you cannot interpret.

`dependencies` inventories required runtime code or instruction payloads, including
external tool implementations. Each entry is `{"reference":"identity or URL","path":"reviewed relative path"}`.
An empty path means the dependency is outside the snapshot and blocks. An in-scope
path must be reviewed text in the manifest. Host-standard runtime libraries are an
explicit out-of-scope trust assumption. Ordinary API data and documentation citations
are not automatically executable dependencies; inspect how their contents are used.

## Gate and consume the result

```sh
python3 -I -B /trusted/skill-sentinel/scripts/preflight.py gate /review/package --manifest /trusted/review/manifest.json --assessment /trusted/review/assessment.json > /trusted/review/result.json
```

The caller chooses the directory. Report fields cannot redirect the scan or relax
limits. The gate re-inventories it, compares the full original manifest, validates the
assessment, retains all mechanical and semantic gaps, and derives output fields.
Duplicate JSON keys, nonfinite numbers, malformed shapes and controls over 2 MiB block.
Missing fields never default to a clean assessment.

| Exit | Decision | Required consumer behavior |
| --- | --- | --- |
| 0 | PROCEED | Complete review with zero findings; still apply host permissions |
| 1 | REVIEW | Complete review with LOW/MEDIUM findings; resolve or accept explicitly |
| 2 | BLOCK | Incomplete, invalid or HIGH/CRITICAL; do not install or run |
| Other, missing/truncated output or timeout | No valid decision | Treat as BLOCK |

`observed_risk=NONE` is compatible with `coverage=INCOMPLETE, decision=BLOCK`.
The compatibility `overall_rating` remains HIGH for that combination, CRITICAL when
there is a CRITICAL finding, and CLEAN only for PROCEED. Never use observed risk alone
as an installation gate. Never let a model replace the helper's decision in automation.

The helper is intentionally conservative: it blocks all links, unsupported binary
formats, containers and identified whole-file encoded binary wrappers. Recognizing a
format is not analyzing its behavior. Embedded/novel encodings and text loaders still
need semantic review. A forged report claiming to have read safe-looking text can be
structurally valid; no schema can prove those claims true. Preserve raw reports and
actual tool traces for evaluation. Manifests identify bytes; they are not signatures or
proof of an immutable view. Use a frozen target and recheck at installation.
