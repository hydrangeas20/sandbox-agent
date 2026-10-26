# Build Log

Concise per-milestone progress entries. Newest last.

## M1 — Specification and threat model
- Goal: define scope, trust boundaries, attacker inputs, assets, mitigations, non-goals and measurable acceptance criteria (AC-1…AC-14).
- Output: `docs/SPEC.md`, `docs/THREAT_MODEL.md` (17 attack paths, each mapped to a planned test).
- Environment note: Docker Hub (`registry-1.docker.io`) is blocked by this build environment's egress policy, so the sandbox base image cannot be pulled here. Plan: keep `python:3.12-slim` as the canonical base in `sandbox/Dockerfile` and bootstrap an equivalent local base image offline for this environment (see M2/M3).

## M2 — Foundation
- Goal: reproducible project skeleton with strict quality gates and an offline default.
- Added `pyproject.toml` (hatchling, `uv.lock`, runtime deps limited to FastAPI/Pydantic/uvicorn), `Makefile` (`lint`, `typecheck`, `test`, `test-docker`, `test-security`, `image`, `demo`, `ci`), GitHub Actions CI (quality job + Docker sandbox job), Ruff (incl. bandit `S` rules), `mypy --strict`.
- `config.py`: frozen Pydantic models; network/rootfs/privilege fields are `Literal`, so relaxing them is a validation error. Env vars restricted to an allowlist.
- Fixture `fixtures/repos/paginator`: 1-indexed paginator with a genuine off-by-one (`start = page * per_page`); 2 of 6 stdlib `unittest` tests fail.
- Offline mode is the default (`SANDBOX_AGENT_OFFLINE=1`); docker tests skip locally when the daemon/image is missing, but CI sets `SANDBOX_AGENT_REQUIRE_DOCKER=1` so a missing daemon is an error.
- Checks: ruff clean, mypy strict clean, 18 tests pass.

## M3 — Isolated execution
- Goal: the only process-spawning path runs untrusted code in a locked-down container, and unavailable controls are errors.
- `sandbox/Dockerfile` (no RUN steps, `USER 10001:10001`); `scripts/bootstrap_base_image.py` builds a shell-less Python 3.12 base offline because Docker Hub is blocked here. CI builds from `python:3.12-slim`.
- `sandbox.py`: `docker create` (argv list, no shell) → `docker inspect` compared field-by-field to the frozen config (network, privileged, caps, no-new-privileges, seccomp not unconfined, read-only rootfs, memory = swap, CPUs, PIDs, ulimits, tmpfs flags, IPC/PID/UTS/userns/cgroupns, devices, log driver, user, exactly one read-only bind mount, env keys) → start only if all match → bounded stdout/stderr readers → `docker kill` on timeout → OOM state from inspect → `docker rm -f` always.
- Fail-closed observed in practice: the first run aborted with `CgroupnsMode is host` (cgroup v1 host); fixed by requesting `--cgroupns private`, not by relaxing the check.
- Workspace is mounted **read-only**; container writes go only to a 64 MiB `noexec,nosuid,nodev` tmpfs.
- Tests: unit tests for args, 21 inspect mutations, 4 mount-tampering cases, mount-source validation and missing docker; 11 Docker runtime tests (only `lo`, TCP/DNS fail, uid/gid 10001, CapEff/CapPrm/CapBnd = 0, NoNewPrivs=1, Seccomp=2, setuid denied, EROFS on rootfs and workspace even for world-writable files, `/tmp` noexec, no planted secrets in env, 600 MB allocation OOM-killed, thread bomb stopped by PID limit, busy loop killed at timeout, 2 MB output truncated, RLIMIT_FSIZE → EFBIG, tampered inspect aborts before start and leaves no container). 66/66 pass.

## M4 — Workspace security
- Goal: a disposable copy of the fixture that host code can only touch through validated paths.
- `workspace.py`: private root (`mkdtemp`, 0700) + `repo/` copy. Copy never follows symlinks (links preserved as inert entries), rejects FIFOs/devices, enforces entry and byte limits, normalises file modes to 0644 (drops setuid/exec bits), and cleans up on failure.
- `resolve()`: lexical rules (no `..`, absolute, `~`, drive letters, backslash, NUL/control chars, length/depth caps) then per-component `lstat`; **any** symlink component is refused, including links pointing inside the workspace; only regular files/dirs accepted.
- Reads: `O_NOFOLLOW`, size-capped, UTF-8 only. Writes: existing files only, temp file + re-check + atomic `os.replace` (never follows a link at the target).
- `FixtureRegistry` maps a regex-validated *name* to a direct, non-symlink child of the registry; `tree_manifest()` hashes a tree without following links (used to prove the fixture is unchanged).
- Cleanup is idempotent, refuses paths it did not create, and does not follow symlinks.
- Tests: 46 workspace tests (15 traversal variants × read/write/resolve, 5 symlink variants, link swapped after copy, dir link in the middle, FIFO, binary, size and copy limits, mode stripping, cleanup safety, fixture-name validation) + 1 Docker test confirming the container cannot write or create links in the real workspace. 113/113 pass.

## M5 — Tool contracts
- Goal: structured, validated tools; no unrestricted shell.
- Tools: `list_files`, `read_file` (line-numbered slices), `search` (literal substring only — no host-side regex, avoiding ReDoS), `apply_patch`, `run_tests`, `finish`. Inputs are Pydantic models with `extra="forbid"` and length bounds; outputs are `ToolResult` with distinct `policy_denial` / `invalid_arguments` / `execution_error` kinds so budgets can treat them differently.
- `policy.py`: `run_tests` takes a command *name* (`unittest`) mapped to fixed argv, plus an optional selector matching `^tests(\.ident){0,6}$` — blocks flag injection (`--help`), arbitrary callables (`os.system`), and shell metacharacters.
- `patch.py`: exact-match search/replace edits; each `old` must match exactly once; all edits validated in memory and resulting sizes checked before any write (atomic for validation failures).
- Tests: 47 new (unknown tools incl. `_tool_finish`/`__init__` dispatch probes, 10 policy-denial cases that assert the runner was never called, 9 invalid-argument cases, patch ambiguity/no-match/no-op/traversal/size/atomicity, 6 malformed edit payloads, real sandbox `run_tests` on the buggy fixture → 6 run, `failures=2`). 161/161 pass.

## M6 — Bounded agent orchestration
- Goal: provider-neutral controller that owns budgets and status; deterministic offline provider; optional real adapter.
- `agent.py`: one linear loop with explicit exits — cancellation (checked before each provider call *and* before executing the returned action), `max_iterations`, `max_tool_calls`, `max_wall_clock_s`, `max_policy_denials`, `max_invalid_outputs`, bounded observations. Raw provider output is validated into `AgentAction` (`extra="forbid"`, tool-name pattern) by the controller, not the adapter.
- Status is computed, never claimed: `succeeded` requires ≥1 applied patch **and** a full-suite (no selector) passing `run_tests` after the last patch. Sandbox failures during `run_tests` end the run as `sandbox_error` (fail closed).
- Providers: `ScriptedProvider` (plan steps with optional expectations — if the observed world differs, it finishes with a "diverged" note instead of claiming a fix), `LoopingProvider`, `InjectionFollowingProvider` (simulated fully-compromised model, used in M9), and `AnthropicProvider` (stdlib HTTP, forced single tool call, tool results labelled as untrusted data). **Real-provider integration is unverified**: only request construction/parsing is tested with a stub transport; no credentials were available.
- Tests: 34 new (status semantics incl. selector-only and pre-patch passes not counting, all four budgets, two cancellation points, 11 invalid-output shapes, recovery, provider exceptions, denial abort, sandbox fail-closed, observation bounding, adapter key handling and response parsing). 195/195 pass.

## M7 — End-to-end coding task
- Goal: agent diagnoses, patches and verifies a real bug through the real sandbox; prove the fixture is untouched.
- `service.py` (`run_task`): resolves fixture by name, hashes it, creates a workspace, runs `preflight()` (fail closed), runs the controller, computes a host-side `difflib` diff, re-hashes the fixture (a mismatch forces `failed` with an INTEGRITY FAILURE reason), cleans up. `cli.py` (`run`, `demo`, `preflight`, `fixtures`, `serve`) and `api.py` (`/healthz`, `/fixtures`, `POST /tasks`, single-flight with HTTP 429).
- Observed demo: unpatched suite 6 run / `failures=2` → search → read → patch `start = page * per_page` → `(page - 1) * per_page` → 6 run / OK → `SUCCEEDED` in ~1.8 s; fixture SHA-256 identical before/after; no workspaces or containers left behind.
- Tests: E2E (status, diff content, independent manifest check, original still contains the bug, tool sequence, before/after test results, no leftovers), API task run, CLI demo exit code; no-Docker tests for API validation (path-like fixture names → 404, extra/oversized fields → 422), offline mode refusing a real provider, missing Docker → `sandbox_error` with the agent never started, and an AST check that only `sandbox.py` imports `subprocess` and nothing calls `eval`/`exec`/`os.system`/`shell=True`. 212/212 pass (1 third-party deprecation warning from Starlette's test client).

## M8 — Observability
- Goal: traces sufficient to reconstruct every action without exposing secrets.
- `trace.py`: versioned envelope (`v`, `cid`, gap-free `seq`, UTC `ts`, `t_ms`), payloads cannot overwrite envelope fields, values coerced to JSON-native types. Redaction **at emit time**: registered provider keys, values of well-known credential env vars, patterns (Anthropic/OpenAI/GitHub/Slack/AWS keys, bearer tokens, PEM private keys, `password=`-style assignments) and credential-named dict keys. JSONL writer/loader.
- Events: per-tool `tool_start`/`tool_end` with `duration_ms` and container resource outcomes, `provider_action` with provider latency and full args, `policy_denial` with the rule ID, preflight details, and a `task_end` resource summary. Schema documented in `docs/SPEC.md` §8.
- Tests: envelope/spoofing, 7 planted-secret patterns, registered + env secrets, short-value non-redaction, header keys, JSONL roundtrip; Docker E2E with a planted API key in the environment *and* the task text (absent from result JSON and trace file), call-ID pairing, resource summary, and a replay test that rebuilds the provider from `provider_action` events and reproduces an identical diff and tool sequence. 226/226 pass.
