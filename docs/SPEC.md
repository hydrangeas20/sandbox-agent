# Sandbox Coding Agent — Specification (MVP)

Status: MVP, single-user, local. Version 0.1.

## 1. Purpose

Sandbox Coding Agent accepts a natural-language coding task against a small,
explicitly selected fixture repository, lets an LLM-driven agent investigate and
patch a disposable copy of that repository through a narrow set of structured
tools, runs the repository's tests **only inside a locked-down Docker
container**, and returns the resulting diff, test outcome, task status and a
structured execution trace.

The project's thesis is *capability containment*: the system must stay within
its policy even when the model is wrong, confused, or actively following
instructions injected through repository content.

## 2. Scope

In scope:

- One task at a time against one fixture repository chosen by name from a
  registry directory (`fixtures/repos/<name>`). Arbitrary host paths are not
  accepted by the API or CLI.
- Tools: `list_files`, `read_file`, `search`, `apply_patch`, `run_tests`,
  `finish`. There is no general shell tool.
- A bounded agent loop with a provider-neutral interface, a deterministic
  scripted provider (used in CI and the offline demo), and an optional
  Anthropic Messages API adapter.
- A FastAPI service (`POST /tasks`, `GET /healthz`, `GET /fixtures`) and a CLI
  (`sandbox-agent run | demo | preflight | fixtures`).
- JSON Lines execution traces with correlation IDs and redaction.

Out of scope (non-goals):

- Hostile multi-tenant production workloads; defence against kernel or
  container-runtime escapes.
- Arbitrary shell execution, package installation, or network access from the
  sandbox.
- Multi-agent orchestration, Kubernetes, browser UI, cloud deployment.
- Persisting tasks across process restarts; authentication on the API (it binds
  to `127.0.0.1` by default).
- Proving that a model *resists* prompt injection. The claim is narrower: an
  injected instruction cannot cause actions outside the tool policy.

## 3. Components

| Component | Module | Responsibility |
|---|---|---|
| Execution config | `sandbox_agent.config` | Frozen Pydantic models holding every isolation and budget setting. |
| Sandbox runner | `sandbox_agent.sandbox` | Builds `docker create` arguments, verifies the created container with `docker inspect` before start, enforces timeout and output caps, removes the container. |
| Workspace | `sandbox_agent.workspace` | Disposable copy of the fixture, path validation, symlink and special-file defences, size limits, safe cleanup. |
| Policy | `sandbox_agent.policy` | Command allowlist (named commands mapped to fixed argv), test-selector validation. |
| Tools | `sandbox_agent.tools` | Pydantic input/output contracts and dispatch for every tool. |
| Patch engine | `sandbox_agent.patch` | Validated exact-match search/replace edits, applied atomically. |
| Providers | `sandbox_agent.providers` | `Provider` protocol, `ScriptedProvider`, `AnthropicProvider` (unverified without credentials). |
| Controller | `sandbox_agent.agent` | Bounded loop, budgets, cancellation, error states, final status. |
| Trace | `sandbox_agent.trace` | Structured JSONL events, timings, redaction. |
| Service | `sandbox_agent.service` | Orchestrates one task end to end; computes diff and fixture integrity. |
| Interfaces | `sandbox_agent.api`, `sandbox_agent.cli` | HTTP and command-line entry points. |

## 4. Task lifecycle

1. Caller submits `{fixture, task, provider, budgets?}`.
2. Service resolves the fixture name against the registry (regex
   `^[a-z0-9][a-z0-9_-]{0,63}$`, must be a direct child directory, must not be a
   symlink) and records a SHA-256 manifest of the fixture.
3. A disposable workspace is created under a private temp directory (mode
   `0700`) and the fixture is copied in. Symlinks are copied as links (never
   followed); special files are rejected.
4. The controller runs the loop: provider returns one action → action is
   validated → tool executes under policy → observation is appended → repeat
   until `finish`, a budget is exhausted, cancellation, or a fatal error.
5. `run_tests` executes an allowlisted command in a fresh container with the
   workspace mounted **read-only**.
6. The service computes a unified diff (host-side, `difflib`, no code
   execution), re-hashes the fixture to prove it is unchanged, writes the
   trace, deletes the workspace, and returns a `TaskResult`.

## 5. Task status semantics

The status is computed by the controller; the model cannot declare success.

| Status | Meaning |
|---|---|
| `succeeded` | Model called `finish`, at least one patch was applied, and the most recent `run_tests` after the last patch passed. |
| `failed` | Model called `finish` but the success condition does not hold. |
| `budget_exhausted` | Iteration, tool-call, or wall-clock budget reached. |
| `policy_aborted` | Policy denials reached `max_policy_denials`. |
| `cancelled` | Cancellation requested by the caller. |
| `provider_error` | Provider failed or returned invalid output more than `max_invalid_outputs` times. |
| `sandbox_error` | Isolation could not be applied or verified (fail closed). |

## 6. Default limits

| Limit | Default |
|---|---|
| Container memory / memory+swap | 256 MiB / 256 MiB |
| CPUs | 1.0 |
| PIDs | 64 |
| Open files (`nofile`) | 256 |
| `/tmp` tmpfs | 64 MiB, `noexec,nosuid,nodev` |
| Command timeout | 30 s |
| Captured output per stream | 64 KiB (excess discarded, flagged `truncated`) |
| Max file read | 256 KiB |
| Fixture copy | ≤ 2,000 entries, ≤ 10 MiB |
| Patch | ≤ 20 edits, ≤ 64 KiB per replacement, resulting file ≤ 256 KiB |
| Search results | ≤ 200 matches, query ≤ 200 chars |
| Agent iterations / tool calls | 12 / 20 |
| Wall clock per task | 300 s |
| Policy denials before abort | 3 |
| Invalid provider outputs before abort | 2 |

## 7. Measurable acceptance criteria

Each criterion maps to automated tests (see `tests/`). "Docker" tests need a
running daemon and the sandbox image; they are skipped only when Docker is
absent, and the skip is reported, never silently treated as a pass.

| ID | Criterion | Verified by |
|---|---|---|
| AC-1 | Code from the workspace never executes on the host: the only process-spawning code path is `docker`, with argv built from a frozen config (no shell). | `test_sandbox_args.py`, `test_no_host_exec.py` |
| AC-2 | Container has no network: DNS and TCP connects fail; only `lo` exists. | `test_sandbox_docker.py::test_network_disabled` |
| AC-3 | Container runs as UID 10001, all capabilities dropped (`CapEff=0`), `NoNewPrivs=1`, not privileged, root filesystem read-only, workspace read-only. | `test_sandbox_docker.py` |
| AC-4 | Memory over-allocation is OOM-killed; fork bomb is stopped by the PID limit; a busy loop is killed at the timeout. | `test_sandbox_docker.py`, `test_adversarial.py` |
| AC-5 | If any requested isolation setting is not present in `docker inspect` of the created container, the run aborts with `SandboxIsolationError` and the container is removed before start. | `test_sandbox_args.py::test_verify_*` |
| AC-6 | Path traversal (`..`, absolute, NUL, backslash), symlink escapes (file and directory symlinks, including links that point inside the workspace), and special files are rejected for every tool. | `test_workspace.py`, `test_adversarial.py` |
| AC-7 | Only allowlisted commands run; unknown tool names, unknown command names and malformed selectors are denied and traced as `policy_denial`. | `test_tools.py`, `test_adversarial.py` |
| AC-8 | Output larger than the cap is truncated and flagged; oversized file reads and patches are rejected. | `test_sandbox_*`, `test_workspace.py`, `test_patch.py` |
| AC-9 | Loop terminates within budgets for a provider that never finishes; cancellation stops it before the next action. | `test_agent.py` |
| AC-10 | Invalid provider output (bad JSON, unknown action, schema violation) is handled as an error state, not a crash. | `test_agent.py`, `test_adversarial.py` |
| AC-11 | End-to-end: on the `paginator` fixture the scripted agent runs failing tests, patches the bug, re-runs passing tests, and returns a non-empty diff with status `succeeded`; the fixture's SHA-256 manifest is identical before and after. | `test_e2e.py` |
| AC-12 | Traces are JSONL, share one correlation ID, include per-tool `duration_ms`, policy denials and container resource outcomes, and contain no secret values (verified with planted secrets). | `test_trace.py`, `test_e2e.py` |
| AC-13 | No API key or host environment variable reaches the container environment. | `test_sandbox_docker.py::test_env_is_minimal` |
| AC-14 | `make ci` (ruff, ruff format check, mypy --strict, full pytest) passes. | CI workflow |

## 8. Trace schema (v1)

Traces are JSON Lines (`runs/<task_id>.trace.jsonl` from the CLI; inline as
`trace` in API responses). Every event carries `v`, `cid` (task ID), `seq`
(1-based, gap-free), `ts` (UTC ISO-8601), `t_ms` (ms since task start) and
`event`. Envelope fields cannot be overwritten by event payloads.

| Event | Key fields |
|---|---|
| `task_start` | `fixture`, `provider`, `task`, `fixture_sha256` |
| `sandbox_preflight` | `server_version`, `security_options`, `cgroup_version`, `image` |
| `agent_start` | `provider`, `budget` |
| `provider_action` | `iteration`, `tool`, `args`, `thought`, `duration_ms` (provider latency) |
| `invalid_provider_output` | `iteration`, `error`, `duration_ms` |
| `tool_start` / `tool_end` | `iteration`, `tool`, `call_id`; end adds `ok`, `error_kind`, `denied_rule`, `duration_ms`, `resources` (container name, `timed_out`, `oom_killed`, stdout/stderr bytes) and a compact `result` (file contents are not traced) |
| `policy_denial` | `iteration`, `tool`, `rule`, `detail` |
| `agent_end` | status, reason, counters, `final_tests_passed`, `summary` |
| `sandbox_error` / `provider_error` / `workspace_error` | `error` |
| `task_end` | `status`, `reason`, `files_changed`, `fixture_unchanged`, `duration_ms`, `resources` (sandbox runs, sandbox ms, timeouts, OOM kills, output bytes, policy denials) |

`provider_action` events contain the full tool arguments, so the action
sequence can be replayed from the trace alone (`test_trace_is_sufficient_to_replay`).
Redaction is applied at emit time (registered provider keys, well-known
credential env vars, credential patterns, credential-named dict keys); a patch
that itself contains secret-shaped text is therefore not exactly replayable.
