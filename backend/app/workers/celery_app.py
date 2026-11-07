"""Celery distributed task queue configuration."""

from celery import Celery

from app.config import settings

celery_app = Celery("trustlens")

celery_app.conf.update(
    broker_url=settings.CELERY_BROKER_URL,
    result_backend=settings.CELERY_RESULT_BACKEND,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=60,
    task_soft_time_limit=45,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_routes={
        "app.workers.scan_tasks.*": {"queue": "scans"},
    },
)

# Autodiscover tasks from workers package
celery_app.autodiscover_tasks(["app.workers"])
