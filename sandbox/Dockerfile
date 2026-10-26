# Sandbox runner image. Untrusted repository code runs only in containers from this image.
#
# Canonical base: python:3.12-slim (pin by digest for production use).
# Offline fallback: `make image-offline-base` builds a shell-less local base from the
# host interpreter (see scripts/bootstrap_base_image.py and docs/DECISIONS.md).
#
# The base filesystem is copied onto `scratch`, which discards every image-level
# setting of the base (ENV such as GPG_KEY/PYTHON_*, ENTRYPOINT, CMD, ONBUILD). The
# only environment is the one declared below, and the host verifier requires the
# container environment to match it exactly (SECURITY_REVIEW SR-02).
#
# There are no RUN steps, so the same Dockerfile works on a base without a shell.
# Isolation (network, caps, seccomp profile, limits, read-only rootfs) is applied at
# `docker create` time, verified by inspect, and attested again from inside the
# container by entry.py before any untrusted code runs.
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE} AS base

FROM scratch
COPY --from=base / /
COPY entry.py /opt/sandbox-agent/entry.py

LABEL org.opencontainers.image.title="sandbox-agent-runner" \
      org.opencontainers.image.description="Locked-down test runner for Sandbox Coding Agent"

ENV PATH=/usr/local/bin:/usr/bin:/bin \
    HOME=/tmp \
    LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

USER 10001:10001
WORKDIR /workspace
