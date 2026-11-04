"""SafeContain AI Enterprise Backend Application Server.

Entry point for FastAPI server mounting security middlewares, v1 REST endpoints,
CORS policies, and automatic scenario initialization.
"""

from contextlib import asynccontextmanager
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

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
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/api/v1")
@app.get("/status")
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


# Static file serving and SPA fallback for unified production deployment
FRONTEND_DIST_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if FRONTEND_DIST_DIR.exists() and (FRONTEND_DIST_DIR / "index.html").is_file():
    assets_dir = FRONTEND_DIST_DIR / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="frontend_assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
            raise HTTPException(status_code=404, detail="Resource not found")
        target_file = FRONTEND_DIST_DIR / full_path
        if full_path and target_file.is_file():
            return FileResponse(target_file)
        return FileResponse(FRONTEND_DIST_DIR / "index.html")
else:
    @app.get("/")
    def default_root():
        return root_status()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", settings.PORT))
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port, reload=False)

