"""API v1 master router incorporating endpoint sub-routers."""

from fastapi import APIRouter

from app.api.v1.endpoints import admin, auth, certificates, dashboard, health, reports, scans, users

api_v1_router = APIRouter()

# Core routes
api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(users.router)
api_v1_router.include_router(scans.router)
api_v1_router.include_router(certificates.router)
api_v1_router.include_router(dashboard.router)
api_v1_router.include_router(reports.router)
api_v1_router.include_router(admin.router)

# Route aliases matching UI/UX conventions
api_v1_router.include_router(
    admin.router, prefix="/moderation", tags=["Moderation & Administration"]
)
