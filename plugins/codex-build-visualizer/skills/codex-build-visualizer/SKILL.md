---
name: codex-build-visualizer
description: Visualize and audit an active Codex coding task as a privacy-enhanced live timeline and replay dashboard. Captures plans, tools, real Git diffs, commands, tests, approvals, subagents, context compaction, official or estimated Token usage, effective user Tokens, context savings, and exports. Use when the user asks to watch, visualize, trace, replay, demo, document, or optimize Codex's code-writing process. Do not use for ordinary coding tasks unless the user explicitly wants process visualization or an observable build trace.
---

# Codex Build Visualizer

Create an inspectable record of observable coding work. Record actions and results, never prompts, raw user messages, source contents, hidden reasoning, credentials, or private chain-of-thought.

Require Python 3.9 or newer. Use Git when available for exact clean-baseline diffs; otherwise use the bounded filesystem fallback.

## Start a trace

Resolve this skill's directory from the loaded `SKILL.md`, then set:

```bash
visualizer_script="<skill-directory>/scripts/trace.py"
project_root="<absolute-project-root>"
```

Initialize before editing:

```bash
python3 -B "$visualizer_script" init \
  --root "$project_root" \
  --title "<short user-facing task title>" \
  --lang auto --privacy standard
```

Choose one privacy mode:

- `strict`: hide project name, command lines, identifiers, raw excerpts, and replace public file paths with stable aliases.
- `standard`: show sanitized relative paths and command lines, but no output excerpts.
- `demo`: show the standard trace and explicitly requested sanitized output excerpts. Use only for a user-approved demonstration.

Share the printed dashboard path in the first useful progress update. A new `init` archives the prior trace.
Generated trace files use owner-only POSIX modes and a trace-local `.gitignore`, so they do not dirty a Git worktree. Windows mode bits do not establish owner-only ACLs: use a project directory whose Windows ACL already limits access to the current user. Windows rejects observed reparse-point components, but cannot provide POSIX `dirfd`-level race guarantees. Refuse a project whose managed trace path uses unsafe links; do not work around that refusal.

The dashboard supports literal search, kind/status/Agent filters, bounded 100-event pages, replay, Token trends with an accessible table, privacy-safe Agent lanes, and comparison with up to 20 prior runs. It polls a small revision file and reloads the full trace only when the generation or revision changes. Standalone exports do not poll or request local files.

## Choose capture mode

Prefer the most automatic mode available. Never read a transcript file to populate the dashboard.

### Project Hooks

When the user asks for automatic visualization, install the generated project-local hooks:

```bash
python3 -B "$visualizer_script" hooks --root "$project_root" --install
```

Automatic debounced workspace snapshots are enabled by default. Tune or disable them without disabling lifecycle capture:

```bash
python3 -B "$visualizer_script" hooks --root "$project_root" --install \
  --auto-snapshot --snapshot-debounce-ms 1200
python3 -B "$visualizer_script" hooks --root "$project_root" --install \
  --no-auto-snapshot
```

The installer merges with an existing `.codex/hooks.json`. Tell the user that Codex requires project trust and review of new non-managed hooks through `/hooks`. The hook adapter records only lifecycle metadata:

- session start/end;
- tool completion and observable duration;
- edit notifications after supported write tools, followed by one background snapshot after the debounce window;
- approval requests;
- automatic or manual context compaction;
- subagent start/stop;
- turn completion.

It deliberately does not configure `UserPromptSubmit` and never reads `transcript_path`, `prompt`, tool payload contents, tool output contents, or agent messages.

The background worker does not sleep or scan while holding the trace lock. It binds each scan to the current trace generation and discards stale results after reinitialization, manual snapshots, or later edits. A failed write tool can still schedule a snapshot because it may have partially changed the workspace.

### App Server or `codex exec --json`

For an event stream, pipe newline-delimited JSON into the ingestion adapter:

```bash
<event-producing-command> | python3 -B "$visualizer_script" ingest \
  --root "$project_root" --source app-server
```

For non-interactive Codex:

```bash
codex exec --json "<task>" | python3 -B "$visualizer_script" ingest \
  --root "$project_root" --source codex-jsonl
```

The adapter accepts plan, diff, command, file-change, tool, subagent, approval, error, compaction, and Token-usage events. It discards user-message, agent-message, reasoning, approval reasons, error messages, raw diff, and command-output bodies after deriving safe counts and summaries.

Treat `thread/tokenUsage/updated` values as exact only when they arrive directly from an active App Server stream. A manually supplied source label is provenance metadata, not cryptographic verification.
For `codex exec --json`, accept exact per-turn usage only from the official top-level `turn.completed.usage` shape. Ignore App Server Token event shapes carried through that source label.

### Manual fallback

If Hooks or an event stream are unavailable, keep the dashboard current explicitly.

Add plan steps:

```bash
python3 -B "$visualizer_script" plan --root "$project_root" \
  --id inspect --title "Inspect the project" --status in_progress
python3 -B "$visualizer_script" plan --root "$project_root" \
  --id implement --title "Implement the change" --status pending
python3 -B "$visualizer_script" plan --root "$project_root" \
  --id verify --title "Run checks" --status pending
```

Update a plan item only when its real status changes. Allowed states are `pending`, `in_progress`, `completed`, and `blocked`.

Record concise factual milestones:

```bash
python3 -B "$visualizer_script" event --root "$project_root" \
  --kind note --title "Selected the existing router pattern" \
  --detail "Keeps the endpoint consistent with neighboring modules." \
  --status info
```

Snapshot after each coherent edit batch:

```bash
python3 -B "$visualizer_script" snapshot --root "$project_root" \
  --title "Implemented request validation"
```

Use `snapshot --full` for a verification boundary or when bypassing the incremental fingerprint cache matters. Normal snapshots reuse unchanged fingerprints, check file metadata before and after reads, and treat unstable or truncated scans as partial rather than claiming unconfirmed deletions.

When the repository is clean at `init`, the script uses the initial Git commit to report real added and deleted lines. For a dirty or non-Git baseline, it clearly labels line counts as net line deltas. It never stores source contents to reconstruct a private baseline.

## Run and verify commands

Run checks through the wrapper when practical:

```bash
python3 -B "$visualizer_script" run --root "$project_root" \
  --kind test --label "Unit tests" -- pytest -q
```

The wrapper streams output live, records exit status and duration, and extracts count-only summaries for common pytest, Rust, Jest-style, and Gradle-style results. It does not save raw output by default.

The timeout wrapper terminates the launched process group. A child that deliberately detaches into a new operating-system session can outlive that group on platforms without job or cgroup containment, so this wrapper is observability tooling, not a security sandbox.

Only in `demo` mode, and only when the user explicitly wants a sanitized excerpt:

```bash
python3 -B "$visualizer_script" run --root "$project_root" \
  --kind test --label "Unit tests" --include-output -- pytest -q
```

Do not wrap commands that print environments, credentials, private data, signed URLs, or large logs. If a command must run normally, record only its observable result afterward. Never claim success before observing the exit status.

## Track Token usage and context optimization

Treat Token reporting as telemetry with explicit provenance. Never infer an exact value from text length, wall-clock duration, or account limits.

Build a compact active-requirement ledger after reading the request. Keep one copy of each still-active requirement, decision, constraint, and acceptance check. Do not save the ledger text in the trace.

Optimize context throughout the task:

- Search narrowly with `rg` before opening large files.
- Read only relevant ranges and references.
- Summarize large tool output once and reuse the summary.
- Deduplicate repeated instructions while preserving the latest correction.
- Keep stable background information in a short checkpoint.
- Avoid dependency trees, generated files, full diffs, and long logs unless required.

Record exact model Token counts only from an official per-session or per-response source:

- App Server `thread/tokenUsage/updated`;
- Codex TUI `/status`;
- OTel `response.completed` counts;
- API response `usage` fields.

Import a bounded official payload instead of copying numbers by hand when available. Automatic detection accepts exactly one recognized API usage, OTel `response.completed`, or Codex `/status` shape and rejects ambiguous or arbitrary nested numbers:

```bash
python3 -B "$visualizer_script" tokens --root "$project_root" \
  --input usage.json --adapter auto
```

For adapters or manual sources with stable counters, use `--semantics cumulative`; per-turn/per-response samples use `delta`, and point-in-time context observations use `snapshot`. Optional `--sample-id` and `--scope` deduplicate retries without publishing the raw identifiers. A cumulative decrease is recorded as a reset baseline and never as negative usage.

```bash
python3 -B "$visualizer_script" tokens --root "$project_root" \
  --label "Exact session usage" \
  --source app-server --quality actual \
  --model-input 18420 --cached-input 9600 \
  --model-output 2140 --reasoning-output 780 \
  --method "thread/tokenUsage/updated"
```

Do not use account-level `/usage` totals as the current task's Token count.

Track user-context effectiveness separately:

- `user-visible`: tokens in visible user messages considered for this task.
- `effective-user`: tokens in the deduplicated active-requirement ledger. Always mark this as derived relevance, even if tokenization is exact.
- `candidate-context`: context that could have been loaded before selection or compaction.
- `retained-context`: context kept after optimization.
- `saved`: `candidate-context - retained-context`; avoided context, not guaranteed billing or quota savings.

```bash
python3 -B "$visualizer_script" tokens --root "$project_root" \
  --label "Context optimization" \
  --source estimate --quality estimated \
  --user-visible 920 --effective-user 360 \
  --candidate-context 12800 --retained-context 4100 \
  --method "Deduplicated corrections; loaded targeted ranges"
```

Refresh metrics after major context loads, compaction, optimization, and before finishing. Preserve earlier Token events for replay. Keep `EXACT`, `ESTIMATE`, `DERIVED`, and `MIXED` labels visible. Never present effective-user Tokens as an official OpenAI metric.

## Export and finish

Export the privacy-filtered current trace when the user wants a portable artifact:

```bash
python3 -B "$visualizer_script" export --root "$project_root" --format html
python3 -B "$visualizer_script" export --root "$project_root" --format markdown
python3 -B "$visualizer_script" export --root "$project_root" --format json
```

The HTML export is standalone and does not require a web server.

Before any export is written, the script scans the complete privacy-filtered payload. With the default `--privacy-check auto`, a risky standard/demo projection is regenerated in strict mode; if risk remains, nothing is written. Use `--privacy-check fail` to refuse instead of falling back, `--strict` to force strict mode, and `--include-history` only when the user explicitly wants privacy-minimized prior-run summaries:

```bash
python3 -B "$visualizer_script" export --root "$project_root" \
  --format html --strict --include-history
```

Verify the private checkpoint, hash-chained recovery journal, public projection, and privacy indicators before sharing or repairing generated public files:

```bash
python3 -B "$visualizer_script" verify --root "$project_root"
python3 -B "$visualizer_script" verify --root "$project_root" --repair-public
```

`--repair-public` is allowed only after private integrity verifies. SHA-256 chaining is tamper-evident, not authenticated: a writer who can replace every artifact can recompute hashes.

Complete or block every plan item, then finalize:

```bash
python3 -B "$visualizer_script" finish --root "$project_root" \
  --status completed --summary "Implemented the feature and passed all checks."
```

Use `--status failed` when the task ends unsuccessfully. Finished traces reject later mutations; start a new trace with `init`. In the final response, link the dashboard or requested export and summarize implementation plus verification.

## Privacy and accuracy rules

- Record only observable work: plan state, privacy-filtered relative paths, line counts, sanitized command names, exit status, duration, safe test counts, approvals, compaction, and short result summaries.
- Never record prompts, hidden reasoning, raw model-visible context, source contents, full diffs, environment dumps, credentials, access tokens, personal data, signed URLs, transcripts, or telemetry payload bodies.
- Treat regex redaction as defense in depth, not permission to ingest known secrets.
- Treat Agent lanes as stable aliases for visualization, not authenticated identities or proof of ownership.
- Treat the dashboard as privacy-enhanced rather than proof that arbitrary input is secret-free. Strict mode removes user-supplied titles, summaries, event details, plan labels, commands, identifiers, and real paths from public artifacts; the private local `trace.json` retains sanitized operational metadata.
- On POSIX, the local `trace.json` is mode `0600`; on Windows, rely on the containing directory's ACL. Public exports remain privacy-filtered but must still be reviewed before sharing.
- The replay retains at most 5,000 recent events. When older events are omitted, the CLI, public state, and dashboard show the omitted count; start a new trace if a complete longer history is required.
- Keep event details under two sentences and prefer evidence such as “12 tests passed.”
- Keep failed checks visible even if a retry later passes.
- Do not start a web server unless the user asks.

## Operations

- `init`: capture a privacy-enhanced baseline.
- `hooks`: print or merge optional lifecycle hooks.
- `hook`: receive one trusted lifecycle hook payload.
- `ingest`: consume App Server or `codex exec` JSONL events.
- `plan`, `event`, `snapshot`: update the observable trace manually.
- `run`: stream a command and record evidence.
- `tokens`: record official, estimated, and derived Token metrics.
- `verify`: validate private recovery state and the public projection; optionally repair only generated public files.
- `export`: create standalone HTML, Markdown, or JSON.
- `finish`: take the final snapshot and close the trace.
- `status`: print a machine-readable summary.

Remove this skill's project-local hooks without disturbing unrelated hooks:

```bash
python3 -B "$visualizer_script" hooks --root "$project_root" --uninstall
```
