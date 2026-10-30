"""SafeContain AI Enterprise Backend Application Server.

Entry point for FastAPI server mounting security middlewares, v1 REST endpoints,
CORS policies, and automatic scenario initialization.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.router import api_router, platform_ctx
from backend.app.core.config import settings
from backend.app.ingestion.connectors import SyntheticScenarioGenerator
from backend.app.security.middleware import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context: initializes baseline synthetic scenario on startup."""
    # Pre-populate scenario if graph is currently uninitialized
    if len(platform_ctx.engine.get_all_nodes()) == 0:
        result = SyntheticScenarioGenerator.generate_national_gateway_scenario()
        for node in result.nodes:
            platform_ctx.engine.add_node(node)
        for edge in result.edges:
            platform_ctx.engine.add_edge(edge)
        platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)
        platform_ctx.active_scenario_name = "Operation Sovereign Gateway (Startup Synthetic)"
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Enterprise Cybersecurity Response Planning, Optimization, Simulation, "
        "and Decision-Intelligence Platform. Government-Ready, Uncertainty-Aware Graph Architecture."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach Security Middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/")
def root_status():
    """Platform identity and service locator."""
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "api_v1_docs": "/docs",
        "health_endpoint": f"{settings.API_V1_PREFIX}/health",
        "provenance_notice": "Decision-support & simulation system. Execution requires authorized human approval.",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
