from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

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


    @app.get("/")
    def root():
        return {
            "system": "CuciSec",
            "status": "running",
            "docs": "/docs"
        }

    return app
