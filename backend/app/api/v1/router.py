"""API v1 master router incorporating endpoint sub-routers."""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, health, scans, users

api_v1_router = APIRouter()

# Core routes
api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(users.router)
api_v1_router.include_router(scans.router)
