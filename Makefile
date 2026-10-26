# Development commands. All targets run offline except `install`.
UV ?= uv
IMAGE ?= sandbox-agent-runner:0.1
BASE_IMAGE ?= python:3.12-slim
export SANDBOX_AGENT_OFFLINE ?= 1

.PHONY: install lint format typecheck test test-unit test-docker test-security adversarial-report image image-offline-base demo ci clean

install:
	$(UV) sync --frozen

lint:
	$(UV) run ruff check .
	$(UV) run ruff format --check .

format:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

typecheck:
	$(UV) run mypy

test-unit:
	$(UV) run pytest -m "not docker"

test-docker:
	$(UV) run pytest -m docker

adversarial-report:
	$(UV) run python scripts/adversarial_report.py

test-security:
	$(UV) run pytest tests/test_adversarial.py tests/test_sandbox_docker.py tests/test_sandbox_args.py tests/test_workspace.py tests/test_workspace_docker.py tests/test_patch.py tests/test_tools.py tests/test_trace.py -v

test:
	$(UV) run pytest

# Canonical image build (needs access to Docker Hub for the base image).
image:
	docker build --build-arg BASE_IMAGE=$(BASE_IMAGE) -t $(IMAGE) sandbox

# For hosts without registry access: bootstrap a minimal base from the host's Python 3.12.
image-offline-base:
	$(UV) run python scripts/bootstrap_base_image.py --tag sandbox-agent-base:local
	docker build --build-arg BASE_IMAGE=sandbox-agent-base:local -t $(IMAGE) sandbox

demo:
	$(UV) run sandbox-agent demo

ci: lint typecheck test

clean:
	rm -rf .mypy_cache .ruff_cache .pytest_cache runs
