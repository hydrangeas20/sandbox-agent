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
`python:3.12-slim` path is exercised only by CI, which has not yet run.

## D11. Single-flight API without authentication

**Decision.** The API binds to `127.0.0.1`, runs one task at a time (HTTP 429
otherwise), and has no auth.

**Why.** MVP scope is a single local operator. Bounding concurrency prevents
the API from fanning out unbounded Docker work.

**Cost.** Not deployable as a shared service. Requests are synchronous; a long
task holds the connection.
