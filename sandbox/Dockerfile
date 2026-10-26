# Sandbox runner image. Untrusted repository code runs only in containers from this image.
#
# Canonical base: python:3.12-slim (pin by digest for production use).
# Offline fallback: `make image-offline-base` builds a shell-less local base from the
# host interpreter (see scripts/bootstrap_base_image.py and docs/DECISIONS.md).
#
# The image intentionally has no RUN steps: nothing is installed, so the same
# Dockerfile works on a base without a shell. Isolation (network, caps, limits,
# read-only rootfs) is applied at `docker create` time and verified by inspect.
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="sandbox-agent-runner" \
      org.opencontainers.image.description="Locked-down test runner for Sandbox Coding Agent"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    LANG=C.UTF-8

USER 10001:10001
WORKDIR /workspace
CMD ["python3", "-c", "print('sandbox-agent-runner ready')"]
