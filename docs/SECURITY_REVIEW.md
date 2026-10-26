# Security Review — Phase 2

Scope: the MVP at `242b36c` (M1–M10), reviewed against the complete trust boundary
(untrusted repository → model action → policy validation → workspace operation →
sandboxed test execution → controller result → audit trace). Reviewer: Claude
(AI), working for and reviewed by the repository owner. Date: 2026-10-26.

**Method.** Each item was treated as a hypothesis and checked against the running
code before any change: a probe or exploit attempt first, then a regression test
written against the pre-fix code, then the fix. Every confirmed finding has a test
that fails on `242b36c` and passes after the fix; the per-test before/after record is
in [`security-review/REGRESSION_EVIDENCE.md`](security-review/REGRESSION_EVIDENCE.md)
(before: **2 passed, 72 failed**, where the 2 passes are false-positive checks;
after: **79 passed, 0 failed**). A passing test is evidence for one property, not
proof that no vulnerability remains.

## Trust boundary as implemented

| Stage | Trusted? | Enforced by |
|---|---|---|
| Operator input (CLI/API) | Trusted, but validated | `TaskRequest` (`extra="forbid"`, bounds); fixture *name* only; API on 127.0.0.1 with a loopback `Host` allowlist (SR-11) |
| Fixture content | **Untrusted** | Descriptor-relative copy: no symlink following, no special files, no hard links, byte/entry limits on bytes actually copied (SR-06–SR-10) |
| Model output | **Untrusted** | Controller validates into `AgentAction`; unknown tools are denials; provider exceptions contained (SR-10); model budgets (P1) |
| Tool arguments | **Untrusted** | Pydantic contracts; command *names* only; selector regex; exact-match patches; protected paths (SR-03) |
| Workspace I/O (host) | Trusted code, untrusted bytes | `O_NOFOLLOW`/`dir_fd` walks, `O_NONBLOCK` + `fstat` (SR-09) |
| Test execution | **Untrusted** | Container from a frozen config, verified by `docker inspect` (incl. pinned seccomp profile and exact env), then **attested from inside** by PID 1 before untrusted code runs (SR-01, SR-02); output, time and memory limits; in-container watchdog (SR-04, SR-05) |
| Result / status | Trusted | Controller-owned status; final-diff allowlist gate (SR-03); fixture integrity hash |
| Audit trace | Trusted, untrusted payloads | Test output, file contents and provider exception text are never traced; emit-time redaction as a backstop (SR-12) |

## Findings

Severity is for this project's stated threat model (single local operator, untrusted
repository and model). Classification: **Confirmed** vulnerability, **DiD**
(defence-in-depth improvement), **FP** (false positive / adequately mitigated),
**Accepted** limitation, **Open** (requires further investigation).

| ID | Finding | Class / Severity | Evidence (pre-fix) | Resolution | Regression test(s) | Residual risk |
|---|---|---|---|---|---|---|
| SR-01 | Seccomp could be silently weakened. `docker inspect` does not record the daemon's default profile, and the verifier only rejected the literal string `unconfined`. | **Confirmed · High** | Daemon started with `--seccomp-profile=allow-all.json`: preflight and verify passed; in-container `unshare(CLONE_NEWUSER)` returned 0. An explicit allow-all profile still showed `Seccomp: 2`, so the old runtime check could not tell. | Pin an explicit profile (Docker's default from moby/profiles `4b8214f` plus an errno-1729 canary on `get_mempolicy`); verify the exact profile JSON in inspect; allowlist all security options (rejects `label=disable`, `apparmor=unconfined`, `systempaths=unconfined`); reject `AppArmorProfile=unconfined` and image entrypoints. A trusted PID 1 entrypoint **attests** seccomp mode, the canary errno, NoNewPrivs, empty capability sets, uid, loopback-only network and read-only mounts before running anything; failure aborts the run. | `test_sr01_*` (6 option variants, tampered profile, args), `test_sr01_pinned_profile_is_enforced`, `test_sr01_runtime_attestation_catches_weak_seccomp[allow_all,unconfined]` (fault injection: verifier disabled) | Kernel/runc vulnerabilities defeat seccomp. AppArmor/SELinux profiles are not positively verified, only "not unconfined". Attestation trusts the image's Python and libc. |
| SR-02 | Image-level environment variables passed verification with any value. | **Confirmed · Medium** | Image with `ENV LD_PRELOAD=… PYTHONPATH=… AWS_SECRET_ACCESS_KEY=…` ran; all three were visible inside. `python:3.12-slim` adds `GPG_KEY`, `PYTHON_*`. | Runner image flattened onto `scratch` (drops all base ENV/ENTRYPOINT/CMD). Inspect must show exactly the configured env plus a per-run nonce; preflight rejects an image whose env differs. PID 1 scrubs Docker's runtime-injected `HOSTNAME`, so the workload sees exactly the configured variables. | `test_sr02_*` (verify, preflight, exact env inside) | A compromised image could still alter binaries; image provenance (digest pinning, signing) is out of scope. Host env never reached the container before either (**FP** for that half: `test_env_is_minimal`, CLI env filter). |
| SR-03 | The agent could make a task "succeed" by editing the tests that decide success. | **Confirmed · High** (result integrity) | Patch deleting the two failing assertions → `succeeded`, with the bug still in the source. | `tests/`, `test/`, test discovery/config (`conftest.py`, `pyproject.toml`, `setup.cfg`, `setup.py`, `tox.ini`, `pytest.ini`, `noxfile.py`, `unittest.cfg`, `.coveragerc`), start-up hooks (`sitecustomize.py`, `usercustomize.py`, `*.pth`), `.sandbox-agent/`, `evals/`, `.github/` are protected in `apply_patch` **and** by a final-diff allowlist at the controller boundary (only modifications of existing, non-protected regular files; otherwise `policy_aborted`). | `test_sr03_*` (3 path spellings, 11 protected files, diff gate with out-of-band write) | **Accepted:** a *source* patch can still subvert the in-process test runner (e.g. monkeypatch `unittest` on import). "Succeeded" means the repository's own suite passed; human diff review remains required. The eval harness adds held-out tests outside the agent's reach. Legitimate test edits need a future explicitly authorised mode. |
| SR-04 | Containers outlived a crashed controller. The timeout lived only in the host process. | **Confirmed · Medium** | Controller SIGKILLed during a 20 s-timeout busy loop: the container was still `Up 43 seconds` and never removed. | (1) PID 1 watchdog enforces `timeout + grace` with no host involvement; it is non-dumpable, so the workload cannot ptrace it or read `/proc/1/*`, and it is immune to in-namespace signals. (2) Containers and workspaces are tagged with the owner (`host:pid:start-ticks`); the next preflight or task start removes orphans of dead owners immediately, and anything past a reap deadline. (3) CLI unwinds on SIGTERM/SIGHUP. | `test_sr04_sigterm_to_controller_cleans_up_promptly` (exit 143, no container or workspace left), `test_sr04_sigkill_to_controller_is_recovered` (watchdog stops it; next `preflight` recovers it), `test_sr04_container_stops_when_host_process_dies`, `test_sr04_pid1_watchdog_cannot_be_killed_or_traced`, reaper decision tests | Between a SIGKILL and the next controller start, a stopped container and workspace remain on disk; a runaway workload lasts at most `timeout + grace` (35 s by default). |
| SR-05 | No total-output limit. The reader kept only 64 KiB but drained everything. | **Confirmed · Medium** | 30 s flood: 13.9 GiB streamed; host CPU ≈ dockerd 14.7 s + CLI 10.6 s + runner 4.7 s. | `max_total_output_bytes` (16 MiB, both streams) kills the container asynchronously so readers keep draining; status `output_limit`. | `test_sr05_output_flood_is_stopped_early[stdout,stderr]`; adversarial flood test strengthened | After the fix the same flood stops in 0.6 s after ~40 MiB (kill latency), using ~0.3 s of host CPU. The overshoot is bounded by kill latency, not the budget. |
| SR-06 | A FIFO in a fixture hung the task forever (integrity hash read it before the copy rejected it). | **Confirmed · Low** (DoS; git cannot store FIFOs) | `tree_manifest` still blocked after 3 s. | Manifest hashes special files by type only; regular files opened `O_NONBLOCK` and `fstat`-checked. | `test_sr06_*` | — |
| SR-07 | Hard links in a fixture were copied, aliasing files outside the tree. | **DiD · Low** (git cannot create hard links) | Hard link to a host file → readable by the agent. | Copy rejects `st_nlink > 1`. | `test_sr07_hard_link_in_fixture_rejected` | — |
| SR-08 | Fixture copy TOCTOU: directory swapped for a symlink after listing was followed; byte limit used `stat` size, not bytes copied. | **DiD · Low** (needs a concurrent local writer) | Fault injection: swapped directory was followed into an outside directory; a file growing during copy bypassed the limit. | Descriptor-relative copy (`O_NOFOLLOW` + `dir_fd`), inode check between listing and open, limits on bytes actually copied. | `test_sr08_*` | Fixture directories are assumed not to be writable by untrusted local users. |
| SR-09 | Workspace read/write re-resolved full paths after validation. | **DiD · Low**: adequately mitigated by the read-only container mount; only another host process could race it | Fault injection: parent swapped after `lstat` → old code read the outside file. | All workspace I/O walks components with `O_NOFOLLOW`/`O_DIRECTORY` relative to the previous descriptor; temp file and `os.replace` relative to the parent fd. | `test_sr09_*` (race + structural check that every `open` is `O_NOFOLLOW` and descriptor-relative) | — |
| SR-10 | Unexpected exceptions (provider transport errors, `PermissionError` while copying, tool bugs) escaped `run_task`. Exception text could carry request data. | **Confirmed · Low** | `ConnectionResetError` from a provider escaped `run_task`. | Controller records unexpected provider exceptions as invalid outputs, **type name only**; tools and service fail closed with structured results; OS errors while copying become `WorkspaceError`. | `test_sr10_*` | — |
| SR-11 | The localhost API accepted any `Host` header, so a DNS-rebinding page could drive it. | **Confirmed · Medium** | `Host: attacker.example` → 200. | `TrustedHostMiddleware` (`127.0.0.1`, `localhost`). | `test_sr11_api_rejects_foreign_host_header` | No authentication. CSRF via `text/plain` was already rejected by FastAPI (**FP**, `test_sr11_text_plain_post_is_rejected`). |
| SR-12 | Redaction gaps: credential-named keys other than a short anchored list, encoded secrets, custom credential env vars, JWT/basic/token auth, URL userinfo, JSON `"api_key": …`. | **Confirmed · Medium** | 20 cases leaked (see evidence). | Primary control is unchanged and verified: test output, file contents and provider exception text never enter the trace (`test_sr12_test_output_never_enters_trace`, already true: **FP** for that part). Backstop widened: credential words in keys at any depth (plural `tokens` excluded so usage counters survive), base64/base64url/hex/URL/JSON encodings of registered secrets, values of any credential-named env var, more formats. | `test_sr12_*` | Pattern redaction cannot catch every secret or encoding. Model `args`/`thought` are traced in full for replay, so a model that echoes a secret it read from the repository is redacted only if the secret matches a pattern. |
| SR-12b | Quadratic-time redaction (ReDoS) on model-controlled strings. **Introduced during this review** by the SR-12 change, caught before commit. | **Confirmed · Medium** (self-introduced; never shipped) | 64 KiB word run: the old 8-case adversarial test took 269 s; the new test did not finish in 300 s on the intermediate code. Passes on `242b36c`. | Bounded, boundary-anchored quantifiers in every pattern. | `test_sr12_redaction_is_not_quadratic` (5 shapes, < 1 s each) | — |
| SR-13 | OOM classification: on cgroup v2 Docker may not set `OOMKilled`, and the test had been relaxed to accept any SIGKILL. | **Confirmed · Low** (test weakness) | CI (cgroup v2): exit 137 with `OOMKilled=false`. | PID 1 reports the workload's signal and the cgroup `oom_kill` counter delta (v1 and v2); `oom_killed` requires SIGKILL **and** a counter increase, while an unrelated SIGKILL is `killed`. Original test made strict again. | `test_memory_limit_oom_killed` (strict), `test_sr13_*` (incl. self-SIGKILL control) | Platform-dependent: requires a readable `memory.events` (v2) or `memory.oom_control` (v1) in the container's cgroup namespace. If neither is readable, `oom_kills` is `null` and classification falls back to Docker's flag. |
| SR-14 | Only the head of each stream was retained, so unittest's summary at the end could be lost. | **Confirmed · Low** (functional) | Reader had no tail. | Head + 8 KiB tail per stream; summary parsed from the tail. | `test_sr14_reader_keeps_head_and_tail` | — |
| SR-15 | Exit report lost when untrusted output ended mid-line (marker glued to the partial line). Found by P3 reliability tests. | **Confirmed · Low** | `test_binary_and_unterminated_output` failed. | Entrypoint starts its exit marker on a fresh line. | `tests/test_reliability.py` | Forged markers are ignored (nonce unreadable by the workload): `test_forged_*`. |
| A-1 | Shared-kernel isolation. | **Accepted · High** for hostile multi-tenant use | — | Documented. gVisor/Kata/Firecracker is the next step. | — | A kernel or runc escape defeats all container controls. |
| A-2 | Docker daemon access is root-equivalent; the controller is trusted. | **Accepted** | — | Documented. | — | — |
| A-3 | Wall-clock budget is checked between iterations. | **Accepted · Low** | — | Bounded: overrun ≤ one provider call (`request_timeout_s`, 60 s) + one sandbox run (`timeout_s`). | `test_wall_clock_budget` | — |
| A-4 | Cancellation does not interrupt a running container. | **Accepted · Low** | — | Bounded by `timeout_s`; checked before and after each provider call. | `test_cancellation_*` | — |
| A-5 | API is unauthenticated (loopback only); a local user could spend real-model budget. | **Accepted · Low** | — | Real provider requires `SANDBOX_AGENT_OFFLINE=0` plus a key in the server's environment; per-task cost cap. | — | — |
| O-1 | Real-model behaviour under injection. | **Open** | Stub-tested only; live evaluation pending the operator's API key. | `sandbox-agent eval --provider anthropic` | — | Containment does not depend on the model, but task success and denial rates do. |

## Controller and agent-loop verification

| # | Property | Result | Evidence |
|---|---|---|---|
| 1 | Model cannot execute host commands | Holds | Only `sandbox.py` spawns processes (AST test `test_no_host_exec_outside_sandbox_module`); no shell tool |
| 2 | Every tool call schema-validated | Holds | `AgentAction` + per-tool Pydantic models with `extra="forbid"` (`test_invalid_arguments`, malformed-output tests) |
| 3 | Unknown tools / invalid args fail closed | Holds | `test_unknown_tool_denied`, `test_malformed_or_hostile_model_output_fails_closed` |
| 4 | Selectors cannot inject arguments | Holds | `test_forbidden_commands_via_pipeline` (`-c`, `--pdb`, `builtins.exec`) |
| 5 | Model cannot modify policy or controller code | Holds. Controller code is outside the workspace; protected paths plus the diff gate cover tests, config and eval files (SR-03) | `test_sr03_*` |
| 6 | Explicit step, time, resource bounds | Holds, with A-3/A-4 caveats | Agent and model budgets, sandbox limits, watchdog |
| 7 | Success from trusted results only | Holds for status, with the SR-03 caveat on what "tests pass" means | Status computed by the controller; `test_model_claiming_success_without_passing_tests_fails` |
| 8 | No unmanaged containers on exceptions, cancellation, timeouts, controller death | Holds (SR-04) | `test_interrupt_during_run_still_removes_container`, SR-04 tests |
| 9 | API cannot bypass controller checks | Holds | API only constructs `TaskRequest` (bounded); 404/422 tests; `Host` allowlist |
| 10 | Injection cannot change tool permissions | Holds | `test_injection_following_provider_is_contained`, eval tasks `invoice-injection`, `hostile-readme` (scripted) |

## Performance

Measured on the build host (2 vCPU, cgroup v1), 5 runs of `make demo`:

| Metric | Before (`242b36c`) | After |
|---|---|---|
| End-to-end task, median | 1,770 ms | 1,495 ms |
| One sandboxed `run_tests`, median | 801 ms | 692 ms |

The extra work (attestation, scrubbed env, watchdog, one extra `inspect`, reaper
`ps`) is within run-to-run noise. The full test suite takes ~85 s (was ~40 s,
mostly the new Docker-backed termination tests).

## Recommendation

No unresolved High-severity finding remains within the stated threat model. A-1
(shared kernel) is a High-severity *accepted* limitation that rules out hostile
multi-tenant use. The MVP is suitable for **further controlled testing** by a
single trusted operator on a dedicated host. It is **not** suitable for production
or for running untrusted repositories on a machine holding valuable credentials.
