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
