import ipaddress
import os
import os.path

from fastapi import FastAPI, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.staticfiles import StaticFiles

from api.routes import rules_route, logs_route, blacklist_route, stats_route
from utils.config import Config


class ManagementAccessMiddleware(BaseHTTPMiddleware):
    """Blocks requests to the management API from untrusted networks."""

    _DENY = JSONResponse(
        status_code=403,
        content={"detail": "Access denied: management API is restricted to trusted networks"},
    )

    def __init__(self, app, allowed_cidrs: list[str]) -> None:
        super().__init__(app)
        self._networks = [ipaddress.ip_network(c, strict=False) for c in allowed_cidrs]

    async def dispatch(self, request: Request, call_next):
        client = request.client
        if client is None:
            return self._DENY
        try:
            addr = ipaddress.ip_address(client.host)
        except ValueError:
            return self._DENY
        if not any(addr in net for net in self._networks):
            return self._DENY
        return await call_next(request)


def create_app(rule_engine=None, firewall_actions=None) -> FastAPI:
    """
    Factory function
    :param rule_engine: RuleEngine instance
    :param firewall_actions: FirewallActions instance
    :return: FastApi app configured
    """

    app = FastAPI(
        title="CuciSec API",
        description="CuciSec REST API",
        version="1.0.0"
    )

    # CORS
    allowed_origins = os.getenv("CUCISEC_ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Management network ACL — added after CORS so it runs first (Starlette wraps in reverse)
    app.add_middleware(ManagementAccessMiddleware, allowed_cidrs=Config.MANAGEMENT_ALLOWED_CIDRS)

    # store instances to app.state -> Dep Injection
    app.state.rule_engine = rule_engine
    app.state.firewall_actions = firewall_actions

    # add routes
    app.include_router(rules_route.router)
    app.include_router(logs_route.router)
    app.include_router(blacklist_route.router)
    app.include_router(stats_route.router)

    @app.get("/api")
    def root():
        return {
            "system": "CuciSec",
            "status": "running",
            "docs": "/docs"
        }

    # Frontend SERVING
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend-cucisec", "dist")

    if os.path.exists(frontend_path):
        assets_path = os.path.join(frontend_path, "assets")
        if os.path.exists(assets_path):
            app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

        # CATCH ALL Route
        @app.get("/{catchall:path}")
        def serve_react_app(catchall: str):

            if catchall.startswith("api"):
                raise HTTPException(status_code=404, detail="API route not found")

            file_path = os.path.join(frontend_path, catchall)
            if os.path.isfile(file_path):
                return FileResponse(file_path)

            return FileResponse(os.path.join(frontend_path, "index.html"))

    return app
