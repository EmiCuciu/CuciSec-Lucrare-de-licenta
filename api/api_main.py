import os.path

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import FileResponse, RedirectResponse
from starlette.staticfiles import StaticFiles

from api.routes import rules_route, logs_route, blacklist_route, stats_route


def create_app(rule_engine=None) -> FastAPI:
    """
    Factory function
    :param rule_engine: RuleEngine instance
    :return: FastApi app configured
    """

    app = FastAPI(
        title="CuciSec API",
        description="CuciSec REST API",
        version="1.0.0"
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # store rule_engine to app.state -> Dep Inj
    app.state.rule_engine = rule_engine


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
                return RedirectResponse(url=f"/{catchall}/")

            file_path = os.path.join(frontend_path, catchall)
            if os.path.isfile(file_path):
                return FileResponse(file_path)

            return FileResponse(os.path.join(frontend_path, "index.html"))

    return app
