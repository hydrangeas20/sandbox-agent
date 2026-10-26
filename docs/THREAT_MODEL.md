# Threat Model — Sandbox Coding Agent (MVP)

Method: STRIDE-style enumeration over explicit trust boundaries. Scope is a
single developer running the service locally. This document is the source of
truth for the adversarial test suite (`tests/test_adversarial.py`).

## 1. Actors

| Actor | Trust | Notes |
|---|---|---|
| Operator | Trusted | Runs the CLI/API, chooses the fixture, holds API keys. |
| Fixture repository content | **Untrusted** | Source, tests, READMEs, comments. May contain prompt injection and hostile code that runs during tests. |
| LLM provider output | **Untrusted** | May be wrong, malformed, or steered by injected content. Treated like any remote input. |
| Tool output (test logs, file contents) | **Untrusted** | Fed back to the model; never interpreted as instructions by the controller. |
| Docker daemon / kernel | Trusted (assumed) | The isolation boundary depends on them being correctly configured and unpatched. |

## 2. Trust boundaries

```
 Operator ──(CLI/API, fixture *name*)──▶ Service (host, trusted code)
                                            │
          ┌─────────────── TB1 ─────────────┤ provider output → validated AgentAction
          │                                 │
   LLM provider (untrusted)                 │
                                            ├── TB2 ── Workspace (host dir, untrusted *content*)
                                            │          accessed only through validated paths
                                            │
                                            └── TB3 ── Docker container (untrusted *execution*)
                                                       --network none, uid 10001, caps dropped,
                                                       read-only rootfs + workspace, limits
```

- **TB1 — model ⇄ controller.** Everything the model emits is parsed into a
  Pydantic `AgentAction`; anything else is an error state.
- **TB2 — host ⇄ workspace bytes.** Host code reads and writes workspace files,
  but only through `Workspace.resolve()`, which rejects traversal, symlinks and
  special files. Host code never imports or executes workspace content.
- **TB3 — host ⇄ container.** The only place untrusted code runs.

## 3. Assets

| Asset | Why it matters |
|---|---|
| A1 Host filesystem (home, SSH keys, cloud credentials) | Exfiltration / tampering. |
| A2 Provider API key | Billing abuse, account compromise. |
| A3 Docker daemon | Root-equivalent on the host. |
| A4 Original fixture repository | Must never be modified by a task. |
| A5 Host availability (CPU, memory, disk, PIDs) | Denial of service. |
| A6 Trace integrity | Needed to reconstruct and audit what happened. |
| A7 Network | Exfiltration channel and lateral-movement vector. |

## 4. Attacker-controlled inputs

1. Task text (operator-supplied, but may be pasted from elsewhere).
2. Every byte of the fixture repository, including file names and symlinks.
3. Code executed by the test command (test files, conftest/imports, module
   import side effects).
4. Model responses (tool names, arguments, JSON shape, size).
5. Test output that flows back to the model.

## 5. Attack paths and mitigations

| ID | Attack path | STRIDE | Mitigation | Test |
|---|---|---|---|---|
| T1 | Injected text in a README tells the model to run `curl … \| sh` or read `~/.ssh/id_rsa`. | E, I | No shell tool exists; `run_tests` takes a command *name* from a fixed allowlist; file tools are confined to the workspace. Tool results are delivered to the model as data in tool-result blocks, and the system prompt states that repository content has no authority. | `test_injection_following_provider_is_contained` |
| T2 | Model requests a tool that does not exist (`bash`, `exec`). | E | Unknown tool → `policy_denial`, counted toward `max_policy_denials`. | `test_unknown_tool_denied` |
| T3 | Path traversal: `../../etc/passwd`, `/etc/passwd`, `a/../../x`, NUL bytes, backslashes, Windows drive prefixes. | I, T | Lexical checks plus component-by-component `lstat` resolution; any `..`, absolute path, NUL, `\`, or `:` drive form is rejected. | `test_workspace.py` |
| T4 | Symlink escape: fixture contains `link -> /etc` or `secret -> ~/.aws/credentials`; patch targets a symlink to overwrite a host file. | I, T | Symlinks are copied as links, never followed. Resolution refuses any symlink component (even ones pointing inside the workspace). Writes use `O_NOFOLLOW` and are re-validated immediately before writing. | `test_symlink_*` |
| T5 | Time-of-check/time-of-use: code running in the container swaps a file for a symlink between validation and a host write. | T | The workspace is mounted **read-only** in the container, so container code cannot create or modify workspace entries at all. Host writes use `O_NOFOLLOW`. | `test_workspace_readonly_in_container` |
| T6 | Hostile test code opens sockets / resolves DNS to exfiltrate. | I | `--network none`; verified via `docker inspect` before start; runtime test asserts only `lo` exists and connects fail. | `test_network_disabled` |
| T7 | Hostile test code tries privilege escalation (setuid binaries, capabilities, `/proc/sys`). | E | Non-root UID 10001, `--cap-drop ALL`, `no-new-privileges`, default seccomp profile, not privileged, read-only rootfs, `/tmp` is `noexec,nosuid,nodev`. | `test_privilege_restrictions` |
| T8 | Fork bomb, memory exhaustion, busy loop, disk fill, log flood. | D | `--pids-limit`, `--memory` = `--memory-swap`, `--cpus`, wall-clock timeout with `docker kill`, tmpfs size cap, `RLIMIT_FSIZE`, `--log-driver none`, bounded stdout/stderr reader. | `test_adversarial.py::test_resource_*` |
| T9 | Container escape via Docker socket or host mounts. | E | Exactly one bind mount (the workspace, read-only), validated to be under the private workspace root; denylist rejects `docker.sock`, `/`, `/home`, `/root`, `/etc`, `~/.ssh`, `~/.aws`, etc. Inspection fails closed on any additional mount. | `test_config_rejects_dangerous_mounts`, `test_verify_rejects_extra_mount` |
| T10 | Isolation silently not applied (old Docker, daemon config, typo). | E | Created container is inspected and every setting compared to the requested config before `docker start`; any mismatch → `SandboxIsolationError`, container removed. Docker missing → `SandboxUnavailableError`; nothing falls back to host execution. | `test_verify_*`, `test_no_docker_fails_closed` |
| T11 | API key leaks into the container or traces. | I | Container env is constructed from an explicit allowlist (never inherited). Provider keys live only in the provider adapter. Traces pass through a redactor that removes registered secret values and common key patterns. | `test_env_is_minimal`, `test_trace_redaction` |
| T12 | Model loops forever or burns budget. | D | Iteration, tool-call and wall-clock budgets; cancellation token. | `test_agent.py` |
| T13 | Malformed / oversized model output or patch (no match, multiple matches, huge replacement, binary). | T, D | Pydantic validation with length limits; exact single-match edits; all edits validated before any write (atomic). | `test_patch.py`, `test_invalid_provider_output` |
| T14 | Task modifies the original fixture. | T | All work happens in a disposable copy; fixture hashed before and after; mismatch is reported as an integrity failure. | `test_e2e.py` |
| T15 | Huge or pathological fixture (deep trees, millions of files). | D | Copy limits on entry count and total bytes; search limits on results and file size. | `test_copy_limits` |
| T16 | Fixture selection used to read arbitrary host directories. | I | API/CLI accept a fixture *name* matched by regex and resolved as a direct, non-symlink child of the registry. | `test_fixture_name_validation` |
| T17 | Trace tampering or gaps. | R | Append-only JSONL with monotonic `seq`, correlation ID on every event; every tool call emits start/end events even on error. | `test_trace.py` |

### Added in the Phase 2 security review

| ID | Attack path | STRIDE | Mitigation | Test |
|---|---|---|---|---|
| T18 | Daemon default or injected option weakens seccomp without the literal `unconfined` (permissive custom profile). | E | Pinned profile verified in inspect; security-option allowlist; in-container attestation with canary errno. | `test_sr01_*` |
| T19 | Image-provided env (`LD_PRELOAD`, `PYTHONPATH`, baked credentials). | E, I | Flattened image; exact env in preflight and inspect; PID 1 scrubs runtime-injected vars. | `test_sr02_*` |
| T20 | Agent (or injected instructions) edits the tests or test configuration that decide success. | T, R | Protected paths in `apply_patch`; controller final-diff allowlist; held-out eval tests. | `test_sr03_*`, `test_evals.py` |
| T21 | Controller dies (SIGKILL, crash) while a container runs. | D | PID 1 watchdog deadline; owner-tagged reaping of containers and workspaces; SIGTERM unwinding. | `test_sr04_*` |
| T22 | Output flood burns host CPU through dockerd and the CLI. | D | Total output budget with asynchronous kill. | `test_sr05_*` |
| T23 | Hostile strings make trace redaction quadratic (ReDoS). | D | Bounded, boundary-anchored patterns. | `test_sr12_redaction_is_not_quadratic` |
| T24 | DNS rebinding to the loopback API. | S, E | Host-header allowlist. | `test_sr11_*` |
| T25 | Workload forges entrypoint markers to spoof attestation or OOM attribution. | S | Per-run nonce held only by non-dumpable PID 1; first/last-line positions. | `test_forged_*` |

## 6. Assumptions

- The Docker daemon, container runtime (runc) and kernel are trusted and
  patched. A kernel or runtime vulnerability can defeat every mitigation in
  TB3.
- The operator does not run the service as a public endpoint. The API binds
  to `127.0.0.1` and has no authentication.
- The sandbox image is built from the repository's `sandbox/Dockerfile` and
  contains no secrets.
- The host user running the service can talk to Docker. **Access to the Docker
  socket is root-equivalent**; the service process is itself trusted code.
- The pinned seccomp profile is applied and attested for every run (T18).
  AppArmor/SELinux are only checked for not being explicitly disabled
  (`apparmor=unconfined`, `label=disable`); their profiles are not positively verified.

## 7. Residual risks and non-goals

- **Docker isolation is a practical MVP boundary, not a guarantee against
  kernel-level escape.** Shared-kernel containers are not suitable for hostile
  production multi-tenant workloads. gVisor, Kata Containers or Firecracker
  microVMs are the appropriate next step and are not implemented.
- No user-namespace remapping (`userns-remap`) is configured; UID 10001 in the
  container is UID 10001 on the host.
- CPU-time side channels and cache timing are out of scope.
- The model can still produce a *wrong* patch or deceptive summary text. The
  status is derived from test results, not model claims. Tests and their
  configuration are protected (T20), but a *source* patch can still subvert the
  in-process test runner, so "succeeded" requires human diff review before use.
- The scripted provider exercises the controller deterministically; it does
  not demonstrate model reasoning. Real-provider behaviour is unverified in CI.
- Denial of service against the Docker daemon itself (e.g. many concurrent API
  requests) is not rate-limited.
