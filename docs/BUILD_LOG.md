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
