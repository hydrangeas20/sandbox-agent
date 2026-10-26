"""Minimal HTTP API. Binds to 127.0.0.1 via `sandbox-agent serve`; no authentication (MVP).

Only one task runs at a time; concurrent submissions get HTTP 429 instead of
queueing unbounded Docker work.
"""

from __future__ import annotations

import threading

from fastapi import FastAPI, HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sandbox_agent import __version__
from sandbox_agent.config import Settings
from sandbox_agent.errors import FixtureError
from sandbox_agent.service import TaskRequest, TaskResult, run_task
from sandbox_agent.workspace import FixtureRegistry

#: The API binds to loopback; requiring a loopback Host header blocks DNS-rebinding
#: attacks where a web page resolves its own hostname to 127.0.0.1 (SR-11).
LOOPBACK_HOSTS = ("127.0.0.1", "localhost")


def create_app(
    settings: Settings | None = None, allowed_hosts: tuple[str, ...] = LOOPBACK_HOSTS
) -> FastAPI:
    cfg = settings or Settings.from_env()
    app = FastAPI(title="Sandbox Coding Agent", version=__version__)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))
    busy = threading.Lock()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "offline": str(cfg.offline).lower()}

    @app.get("/fixtures")
    def fixtures() -> dict[str, list[str]]:
        return {"fixtures": FixtureRegistry(cfg.fixtures_dir).names()}

    @app.post("/tasks")
    def create_task(req: TaskRequest) -> TaskResult:
        if not busy.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="a task is already running")
        try:
            return run_task(req, cfg)
        except FixtureError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        finally:
            busy.release()

    return app
