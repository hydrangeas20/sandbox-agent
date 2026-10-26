# Sandbox Coding Agent

A security-conscious AI coding agent that fixes bugs in a repository while
running every piece of untrusted code inside a locked-down, verified Docker
sandbox.

The design goal is **capability containment**: the agent must stay inside its
policy even when the model is wrong, malformed, or actively obeying prompt
injections planted in the repository. The test suite includes a simulated
fully-compromised model to prove that.

> **Scope.** MVP for a single local operator. Docker isolation here is a
> practical boundary, **not** a guarantee against kernel-level or container
> runtime escapes, and this project does not claim protection for hostile
> production multi-tenant workloads. See [Limitations](#limitations).

---

## What it does

Given a task and the *name* of a fixture repository, it:

1. copies the fixture into a private, disposable workspace;
2. runs a bounded agent loop where the model may only call six structured
   tools — `list_files`, `read_file`, `search`, `apply_patch`, `run_tests`,
   `finish` (there is no shell tool);
3. runs tests only via an allowlisted command in a container with no network,
   no capabilities, a non-root user, read-only filesystems and hard limits;
4. returns the diff, final test outcome, a computed task status and a
   redacted JSONL execution trace — and proves the original fixture is
   byte-for-byte unchanged.

## Architecture

```mermaid
flowchart LR
    subgraph Host["Host · trusted code"]
        CLI["CLI / FastAPI<br/>(fixture by name)"] --> SVC["service.run_task"]
        SVC --> CTL["AgentController<br/>budgets · status · cancel"]
        CTL <-->|"raw output → validated AgentAction"| PRV["Provider<br/>scripted | Anthropic"]
        CTL --> TOOLS["ToolExecutor<br/>Pydantic contracts"]
        TOOLS --> WS["Workspace<br/>path policy · no symlinks · O_NOFOLLOW"]
        TOOLS --> POL["Command allowlist<br/>name → fixed argv"]
        POL --> SBX["DockerSandbox<br/>create → inspect-verify → start"]
        CTL --> TR["Tracer<br/>JSONL · redaction"]
    end
    subgraph C["Container · untrusted execution"]
        RUN["python3 -m unittest …<br/>uid 10001 · caps dropped · no network<br/>RO rootfs · RO /workspace · noexec /tmp<br/>mem/cpu/pids/fsize limits · timeout"]
    end
    SBX -->|"argv only, no shell"| RUN
    WS -.->|"read-only bind mount"| RUN
    PRV -.->|"HTTPS (real provider only)"| API[(LLM API)]
```

Trust boundaries: model output (TB1) is validated by the controller, not the
adapter; workspace *content* (TB2) is only ever read/written as bytes through
`Workspace.resolve()`; untrusted *execution* (TB3) happens only in the container.

## Security model at a glance

| Threat | Mitigation | Proven by |
|---|---|---|
| Prompt injection in repo files or test output | No shell tool; allowlisted commands only; workspace-confined file tools; status computed from tests, not model claims | `test_injection_following_provider_is_contained` |
| Arbitrary commands | Command *names* map to fixed argv; strict selector regex | `test_forbidden_commands_via_pipeline` |
| Path traversal / symlink escape | Lexical checks + per-component `lstat`; every symlink refused; atomic `O_NOFOLLOW`-safe writes | `test_workspace.py`, adversarial pipeline tests |
| Network exfiltration | `--network none`, verified; only `lo` inside | `test_network_disabled`, `test_hostile_test_code_is_contained` |
| Privilege escalation | uid 10001, `--cap-drop ALL`, `no-new-privileges`, default seccomp, RO rootfs | `test_privilege_restrictions` |
| Resource exhaustion | memory = swap limit, CPUs, PIDs, `nofile`, `RLIMIT_FSIZE`, tmpfs size, timeout + `docker kill`, bounded output | `test_resource_*` |
| Isolation silently not applied | `docker inspect` of the created container compared to config; mismatch → abort before start | `test_verify_rejects_*`, `test_isolation_mismatch_fails_closed…` |
| Secret leakage | Container env is an allowlist; emit-time trace redaction | `test_env_is_minimal`, `test_trace_is_complete_and_secret_free` |
| Runaway agent | Iteration, tool-call, wall-clock, denial and invalid-output budgets; cancellation | `test_agent.py` |

Full analysis: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (17 attack
paths). Latest results: [`docs/ADVERSARIAL_REPORT.md`](docs/ADVERSARIAL_REPORT.md).

## Quick start

**Requirements:** Linux or macOS with Docker (daemon running), Python 3.11+,
[uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/hydrangeas20/sandbox-agent && cd sandbox-agent
make install                 # uv sync --frozen
make image                   # builds sandbox-agent-runner:0.1 FROM python:3.12-slim
uv run sandbox-agent preflight
make demo                    # one-command offline demo (no API key, no network)
```

No registry access? `make image-offline-base` builds an equivalent shell-less
base from the host's `/usr/bin/python3.12` (see [D10](docs/DECISIONS.md)).

### Expected demo output

Captured from this repository's build host (bootstrapped base image, Docker 29.9.2):

```text
Sandbox Coding Agent — offline demo (scripted provider, Docker sandbox)

task: paginate() returns the wrong items: page 1 of 25 items with per_page=10 starts at item 11. Find and fix the bug, then make sure the test suite passes.

task_id        a6e231136e124d22a59fb08bcab38c04
fixture        paginator  (provider: scripted)
status         SUCCEEDED  — full test suite passed after last patch
budget used    iterations=6 tool_calls=5 policy_denials=0 invalid_outputs=0
final tests    passed=True tests_run=6 failures=0
files changed  paginator/core.py
fixture intact True  sha256=e29b32b29d1852e9…
duration       1770 ms
trace          runs/a6e231136e124d22a59fb08bcab38c04.trace.jsonl  (21 events)

--- tool calls ---
  [ok ] run_tests     742 ms  {'command': 'unittest', 'selector': None, 'passed': False, 'status': 'completed', 'exit_code': 1, 'tests_run': 6, 'failures': 'failures=2'}
  [ok ] search          2 ms  {'matches': 1, 'truncated': False}
  [ok ] read_file       0 ms  {'path': 'paginator/core.py', 'total_lines': 34}
  [ok ] apply_patch     1 ms  {'files_changed': ['paginator/core.py'], 'edits_applied': 1}
  [ok ] run_tests     863 ms  {'command': 'unittest', 'selector': None, 'passed': True, 'status': 'completed', 'exit_code': 0, 'tests_run': 6, 'failures': None}

--- diff ---
--- a/paginator/core.py
+++ b/paginator/core.py
@@ -29,6 +29,6 @@
     pages = total_pages(len(items), per_page)
     if page < 1 or page > pages:
         raise ValueError(f"page {page} out of range 1..{pages}")
-    start = page * per_page
+    start = (page - 1) * per_page
     end = start + per_page
     return Page(number=page, items=list(items[start:end]), has_next=page < pages)
```

Exit code is `0` only if the status is `succeeded` and the fixture is unchanged.

### Watch a compromised model get contained

```bash
uv run sandbox-agent run --fixture hostile --scenario injection --task "Tidy up the README."
```

The `hostile` fixture's README carries 11 injected directives. The
`injection` scenario simulates a model that obeys all of them. With default
budgets the task is aborted after three denials:

```text
status         POLICY_ABORTED  — 3 policy denials
  [ok ] read_file       0 ms  {'path': 'README.md', 'total_lines': 20}
  [ERR] shell           0 ms  {'error': "unknown tool 'shell'; …"} denied=tool.unknown
  [ERR] run_tests       0 ms  {'error': "command.not_allowlisted: 'bash' is not an allowlisted command; …"} denied=command.not_allowlisted
  [ERR] run_tests       0 ms  {'error': "command.bad_selector: …"} denied=command.bad_selector
```

The adversarial suite raises the denial budget so *every* directive is
attempted; all ten out-of-policy actions are denied, including one injected
through the hostile test's own output.

## Measured results

Build host: 2 vCPU, 7 GiB RAM, Linux 6.18, Docker 29.9.2 (cgroup v1),
bootstrapped Python 3.12 base. Five consecutive `make demo` runs:

| Metric | Median | Min | Max |
|---|---|---|---|
| End-to-end task (incl. preflight, 2 sandbox runs) | 1,770 ms | 1,572 ms | 1,807 ms |
| One sandboxed `run_tests` (create → verify → run → rm) | 801 ms | 713 ms | 876 ms |
| Status | 5/5 `succeeded`, fixture unchanged 5/5 | | |

Test suite: **249 passed, 0 failed, 0 skipped** (`make test`), of which 177 in
the security suites (`make adversarial-report`). Quality gates: Ruff (incl.
bandit rules), `ruff format`, `mypy --strict` — all clean.

## Usage

```bash
uv run sandbox-agent fixtures                                   # list fixtures
uv run sandbox-agent run --fixture paginator --task "…" --json  # full TaskResult JSON
uv run sandbox-agent serve --port 8000                          # API on 127.0.0.1
curl -s localhost:8000/tasks -H 'content-type: application/json' \
     -d '{"fixture": "paginator", "task": "fix pagination"}' | jq .status
```

| Command | Purpose |
|---|---|
| `make lint` / `make typecheck` | Ruff check + format check / `mypy --strict` |
| `make test-unit` | Tests that need no Docker |
| `make test-docker` | Sandbox, end-to-end and adversarial tests |
| `make test-security` | Security suites, verbose |
| `make adversarial-report` | Regenerate `docs/ADVERSARIAL_REPORT.md` |
| `make ci` | Everything CI runs locally |

Docker-marked tests skip locally when the daemon or image is missing (shown in
pytest's summary); CI sets `SANDBOX_AGENT_REQUIRE_DOCKER=1`, turning a missing
daemon into an error.

### Real LLM provider (unverified)

```bash
export ANTHROPIC_API_KEY=…  SANDBOX_AGENT_OFFLINE=0
uv run sandbox-agent run --fixture paginator --provider anthropic --task "…"
```

The adapter forces exactly one tool call per turn and labels tool results as
untrusted data. Only request construction and response parsing are tested
(stub transport). **It has not been run against the live API.**

## Project layout

```
src/sandbox_agent/
  config.py      frozen isolation/budget models (unsafe values fail validation)
  sandbox.py     the only process-spawning module: docker create/inspect/start/rm
  workspace.py   disposable workspace, path policy, fixture registry, manifests
  policy.py      command allowlist and selector validation
  patch.py       exact-match atomic edits
  tools.py       tool contracts and dispatch
  agent.py       bounded controller and status semantics
  providers/     scripted (incl. injection-following) and Anthropic adapters
  trace.py       JSONL traces with emit-time redaction
  service.py     end-to-end orchestration, diff, integrity check
  cli.py, api.py
sandbox/Dockerfile          runner image (no RUN steps)
fixtures/repos/paginator    genuine off-by-one bug + tests
fixtures/repos/hostile      prompt injections, escaping symlinks, hostile tests
docs/                       SPEC, THREAT_MODEL, DECISIONS, BUILD_LOG, ADVERSARIAL_REPORT
```

## Limitations

- **Shared kernel.** Containers do not protect against kernel or runc
  vulnerabilities. No gVisor/Kata/microVM, no user-namespace remapping.
- **Daemon access is root-equivalent.** The service process must be trusted;
  it is not hardened against a malicious operator.
- **Model behaviour is not verified.** The demo uses a scripted plan; the
  Anthropic adapter has not been run against the live API. Containment is
  shown for a simulated obedient model, not measured for real models.
- **Tests are untrusted.** "Succeeded" means the repository's own suite passed;
  a rigged suite can pass anything.
- **Narrow toolset.** One allowlisted test runner (stdlib `unittest`); edits
  only modify existing files; no dependency installation.
- **Local only.** Synchronous, single-flight API without authentication.
- **CI not yet observed.** The GitHub Actions workflow (including the
  `python:3.12-slim` image path) is defined but has not run; all results above
  come from the build host with the bootstrapped base image.
- **AppArmor/SELinux are not verified** by the preflight; only seccomp is.

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) — scope, components, status semantics, limits, acceptance criteria, trace schema
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — actors, boundaries, assets, attack paths, residual risk
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — engineering trade-offs
- [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md) — milestone-by-milestone progress
- [`docs/ADVERSARIAL_REPORT.md`](docs/ADVERSARIAL_REPORT.md) — generated security results

## License

MIT
