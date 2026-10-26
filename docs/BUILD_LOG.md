# Build Log

Concise per-milestone progress entries. Newest last.

## M1 — Specification and threat model
- Goal: define scope, trust boundaries, attacker inputs, assets, mitigations, non-goals and measurable acceptance criteria (AC-1…AC-14).
- Output: `docs/SPEC.md`, `docs/THREAT_MODEL.md` (17 attack paths, each mapped to a planned test).
- Environment note: Docker Hub (`registry-1.docker.io`) is blocked by this build environment's egress policy, so the sandbox base image cannot be pulled here. Plan: keep `python:3.12-slim` as the canonical base in `sandbox/Dockerfile` and bootstrap an equivalent local base image offline for this environment (see M2/M3).
