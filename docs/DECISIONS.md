# Engineering Decisions

Short records of the trade-offs that shaped the MVP. Each lists the decision,
why, and what it costs. These are proposals for review, not settled policy.

## D1. Docker with inspect-verified settings, not a stronger isolation runtime

**Decision.** Run untrusted code in a Docker container created with explicit
flags, then `docker inspect` the *created* container and compare every
isolation setting to the frozen config before `docker start`.

**Why.** Docker is available on every developer machine and CI runner, which
keeps the demo reproducible in one command. Verifying after `create` turns
"we passed the flag" into "the daemon applied it"; this caught a real gap on
the build host (cgroup v1 defaulted to the host cgroup namespace).

**Cost.** Containers share the host kernel. A kernel or runc vulnerability
defeats the boundary. gVisor (`--runtime=runsc`), Kata, or Firecracker would
be the next step; the verifier would then also assert `HostConfig.Runtime`.

## D2. Workspace mounted read-only; host applies patches

**Decision.** The container never writes to the workspace. Patches are applied
by trusted host code through `Workspace.resolve()`; tests run against a
read-only bind mount with a private `noexec` tmpfs for scratch.

**Why.** It removes the TOCTOU class entirely: container code cannot create
symlinks or swap files between the host's path check and its write. It also
makes "writes only in the workspace" true by construction.

**Cost.** Test suites that write next to their sources (bytecode caches,
fixture output) fail unless they use `/tmp`. `PYTHONDONTWRITEBYTECODE=1` covers
the common case. Code generation steps that need a writable tree would need a
copy-in/copy-out step.

## D3. No shell tool; commands are names mapped to fixed argv

**Decision.** `run_tests` accepts an allowlisted command *name* plus an
optional selector matching `^tests(\.ident){0,6}$`. There is no general
`exec`/`shell` tool, and argv is never built from model text.

**Why.** Command allowlists that parse shell strings are a long history of
bypasses. With fixed argv there is nothing to parse. The selector regex blocks
option injection (`--pdb`, `-c`) and loading arbitrary callables
(`os.system`, `builtins.exec`) through unittest's name resolution.

**Cost.** The agent cannot install dependencies, run linters, or run other test
runners. Each new capability is a reviewed code change to `ALLOWED_COMMANDS`.

## D4. Exact-match edits instead of unified diffs

**Decision.** `apply_patch` takes `{path, old, new}` edits; `old` must occur
exactly once; all edits are validated in memory before any write.

**Why.** Unified diffs need a parser with fuzz/offset semantics and fail in
confusing ways on model-generated hunks. Exact-match edits are trivially
validated, cannot silently apply to the wrong location, and give the model an
actionable error ("occurs 3 times").

**Cost.** New files, deletions and renames are not supported in the MVP.
Large refactors need many edits (capped at 20 per call).

## D5. Any symlink component is refused, even if it points inside the workspace

**Decision.** `resolve()` `lstat`s each component and refuses all symlinks.

**Why.** "Resolve and check it stays inside" is subtle (relative links, link
chains, links that become escapes after a rename). Refusing all links is
simple to reason about and test. Links are still *copied* so the repository
is faithful, and listed as `symlink` entries.

**Cost.** Repositories that rely on in-tree symlinks cannot have those paths
read or patched through the link (the real path still works).

## D6. The controller computes status; the model cannot claim success

**Decision.** `succeeded` requires ≥1 applied patch and a full-suite passing
`run_tests` after the most recent patch. Selector-only runs and runs before
the last patch do not count.

**Why.** Agents (and injected text — see the hostile fixture's fake
"SUCCESS" finish) will claim success. Deriving status from observed test
results makes the result auditable.

**Cost.** The repository's tests are themselves untrusted and could be
rigged to pass; the status means "the repository's own suite passed", nothing
stronger.

## D7. Scripted provider with expectations for CI and the demo

**Decision.** CI and `sandbox-agent demo` use a deterministic scripted plan.
Steps can carry expectations about the previous observation (e.g. "the
unpatched suite fails"); if one does not hold, the script finishes with a
"diverged" note instead of continuing.

**Why.** Deterministic, credential-free, and it still exercises the real
sandbox, tools, controller and trace. Expectations prevent the demo from
appearing to "fix" a world it did not observe.

**Cost.** The demo shows orchestration, not model reasoning. The Anthropic
adapter's request/response handling is unit-tested with a stub transport;
**real-provider behaviour is unverified**.

## D8. No LangGraph / agent framework; stdlib HTTP for the provider

**Decision.** A ~200-line controller and a stdlib `urllib` adapter, instead
of an agent framework or vendor SDK.

**Why.** Every budget check and terminal state is visible in one function
for security review; the dependency surface (FastAPI, Pydantic, uvicorn) stays
small. An earlier plan for this project used LangGraph with a judge node and
self-correction retries; those were left out as speculative for the MVP.

**Cost.** No streaming, retries/backoff, or prompt caching in the adapter.

## D9. Emit-time redaction

**Decision.** Events are scrubbed when emitted (registered secrets, known
credential env vars, credential patterns, credential-named keys).

**Why.** Secrets never exist in the in-memory event list, so every consumer
(API response, JSONL file, logs) gets the same redacted data.

**Cost.** Pattern redaction can over-redact ordinary text that looks like
`token=...`, and a patch containing secret-shaped text is not exactly
replayable from the trace.

## D10. Offline base-image bootstrap for restricted build hosts

**Decision.** `sandbox/Dockerfile` has no `RUN` steps and takes `BASE_IMAGE`.
CI uses `python:3.12-slim`. On this build host Docker Hub was blocked by egress
policy, so `scripts/bootstrap_base_image.py` built an equivalent base from the
host's Python 3.12 (interpreter + stdlib + `ldd` closure, deterministic tar,
`docker import`).

**Why.** Keeps one Dockerfile for both paths and avoids routing around the
egress policy. The bootstrapped base has no shell or coreutils, which is a
smaller attack surface than slim.

**Cost.** It is host-specific (needs `/usr/bin/python3.12`). All local test
results in `docs/BUILD_LOG.md` were measured on the bootstrapped image; the
`python:3.12-slim` path is exercised by CI, where it now passes.

## D11. Single-flight API without authentication

**Decision.** The API binds to `127.0.0.1`, runs one task at a time (HTTP 429
otherwise), and has no auth.

**Why.** MVP scope is a single local operator. Bounding concurrency prevents
the API from fanning out unbounded Docker work.

**Cost.** Not deployable as a shared service. Requests are synchronous; a long
task holds the connection.

---

Decisions D12–D18 were added during the Phase 2 security review
(`docs/SECURITY_REVIEW.md`).

## D12. Pin the seccomp profile and attest isolation from inside the container

**Decision.** Pass an explicit seccomp profile (Docker's default plus an errno canary)
on every `docker create`, verify the exact JSON in `docker inspect`, and have a trusted
PID 1 entrypoint (`sandbox/entry.py`) check seccomp, capabilities, NoNewPrivs, uid,
network and read-only mounts before running any untrusted code.

**Why.** Inspect cannot show the daemon's default profile, and a permissive profile
still reports `Seccomp: 2` (SR-01). Inspect proves what was *requested*; attestation
proves what the kernel *enforces* for this process. The canary errno identifies our
profile specifically.

**Cost.** One Python start-up (~10–20 ms) per run; the image must carry the
entrypoint. Profile updates are a reviewed regeneration (`scripts/build_seccomp_profile.py`).

## D13. Flatten the runner image; exact environment

**Decision.** `FROM scratch` + `COPY --from=base / /`, so no base-image ENV,
ENTRYPOINT or CMD survives. The container env must equal the configured env
(plus a per-run nonce), checked in preflight and inspect.

**Why.** An allowlist of keys that accepts any *image-provided* key with any value
is not an allowlist (SR-02).

**Cost.** One large layer instead of shared base layers (no cache sharing with
other images).

## D14. PID 1 watchdog plus owner-tagged reaping for controller death

**Decision.** The entrypoint enforces `timeout + grace` itself. Containers and
workspaces are tagged with the owning controller (`host:pid:start-ticks`), and the
next controller removes orphans of dead owners immediately. The CLI unwinds on
SIGTERM/SIGHUP.

**Why.** The original timeout lived only in the host process (SR-04). PID 1 inside a
PID namespace ignores signals from the workload, and making it non-dumpable blocks
same-uid ptrace. The process start time defeats PID reuse.

**Alternatives rejected.** Docker `--rm` (races with reading the exit state);
`--stop-timeout` (only applies to `docker stop`); a host daemon (more infrastructure).

**Cost.** Owner checks only work for a local daemon; a remote `DOCKER_HOST` falls
back to deadline-based reaping.

## D15. Protect tests and test configuration; final-diff allowlist

**Decision.** Tests, test discovery/config, start-up hooks (`*.pth`,
`sitecustomize.py`), policy and eval directories are not modifiable by the agent,
enforced in `apply_patch` and again by a controller-side check of the final diff.
Approved by the repository owner on 2026-10-26; a mode that allows explicitly
authorised test edits is deferred.

**Why.** The repository's tests decide success; editing them let the agent grade
itself (SR-03).

**Cost.** Tasks that need new or changed tests are refused. This does not stop a
*source* patch from subverting the in-process test runner, which is why human diff
review and held-out evaluation tests remain necessary.

## D16. Budgets for real-model use, enforced before each call

**Decision.** `ModelBudget`: model calls, output tokens per call, total tokens, USD
cost per task, request timeout. Cost is checked before each call against a
worst-case estimate (max of request size and previous billed input, plus a hidden
prompt allowance, plus full `max_tokens`) and updated from the response's `usage`.
Unknown models are refused rather than run without a price.

**Why.** Overspend should be prevented, not merely reported. The pricing table
cites its source and date.

**Cost.** Prices must be maintained by hand. The estimate is conservative, so
budgets stop runs somewhat early.

## D17. Held-out tests in the evaluation harness

**Decision.** Each `fixed` eval task also runs tests stored outside the agent's
workspace, in a fresh sandbox, against a trusted copy of the fixture with the
agent's changed files applied.

**Why.** It gives an independent success signal that the agent cannot see or
edit. `test_wrong_fix_that_passes_visible_tests_fails_heldout` shows the visible
suite being fooled while the held-out check is not.

**Cost.** One extra sandbox run per task.

## D18. Redaction as a backstop, not the primary control

**Decision.** Keep untrusted payloads (test output, file contents, provider
exception text) out of traces entirely. Use bounded, linear-time patterns for the
rest.

**Why.** Patterns cannot catch every secret. A broadened pattern introduced a
quadratic-time regression during the review (SR-12b), caught by a timing test.

**Cost.** Traces cannot be used to debug test output; the model transcript is not
persisted.

## D19. Experiment spend ledger with per-request reservations

**Decision.** Real-model runs require `--experiment-budget-usd`. Before each
request, the adapter reserves the request's worst-case cost in a local ledger
(`runs/spend-ledger.json`, or `--ledger`). The reservation is written atomically
under a file lock (temp file, fsync, rename, directory fsync) before the request is
sent, and is refused if it would exceed the experiment budget. It is settled
afterwards with the actual cost from the API's `usage`.

- Interrupted, killed or crashed requests stay reserved and keep counting, so spend
  is over-counted rather than lost. `sandbox-agent ledger` shows settled and
  unsettled entries.
- Retries are separate requests with their own reservations against the same budget.
- A corrupt ledger blocks further requests.
- Failed requests count as calls. A timeout, reset or 5xx is charged at the
  worst-case estimate because it may have been billed. 400/401/403/404/413/429 are
  charged nothing.
- Prices come from the
  [official pricing page](https://platform.claude.com/docs/en/about-claude/pricing):
  Haiku 5.5 (`claude-haiku-5-5`) at $0.10 / $0.50 per MTok input/output for prompts
  up to 100k tokens (larger prompts are refused); Sonnet 5.5 at $2 / $10. Unknown
  models are refused.
- Each call is traced as a `model_call` event (tokens, cache tokens, estimated cost,
  latency).

**Why.** A post-run record loses the spend of a run that is interrupted mid-request.
A reservation that is durable before the request leaves the process cannot be lost
that way.

**Cost.** Figures are estimates from published prices. The Anthropic Console is
authoritative, and a Console spend limit is the only hard cap. The ledger is local:
it does not carry across GitHub Actions runs (see [`LIVE_SMOKE.md`](LIVE_SMOKE.md)).
