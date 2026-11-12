from datetime import timedelta

from celery import Celery
from redis import Redis
from sqlalchemy import select

from . import models as m
from .config import settings
from .db import SessionLocal, now
from .pipeline import Runner, claim, event

celery = Celery("hackingbara", broker=settings.redis_url)
celery.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    broker_connection_timeout=1,
    task_publish_retry=False,
    task_ignore_result=True,
    broker_transport_options={"visibility_timeout": 3600, "socket_connect_timeout": 1, "socket_timeout": 1},
    beat_schedule={"dispatch-and-reconcile": {"task": "reconcile", "schedule": 15.0}},
)


@celery.task(name="execute_run")
def execute_run(run_id):
    owner = claim(run_id)
    if owner:
        Runner(run_id, owner).run()


@celery.task(name="reconcile")
def reconcile():
    with SessionLocal() as db:
        cutoff = now() - timedelta(seconds=settings.lease_seconds)
        stale = db.scalars(
            select(m.Run)
            .where(m.Run.status.in_(("running", "pausing", "stopping")), m.Run.heartbeat_at < cutoff)
            .with_for_update(skip_locked=True)
        ).all()
        for run in stale:
            # Fail closed: never automatically repeat an uncertain authentication attempt.
            # The process guardian kills scanner groups on worker death.
            run.status = "failed"
            run.error_summary = "Worker heartbeat expired; partial results preserved"
            run.ended_at, run.lease_owner = now(), None
            db.get(m.Scan, run.scan_id).last_status = run.status
            event(db, run, "lease_expired", run.error_summary, "error")
        queued = db.scalars(
            select(m.Run.id)
            .where(m.Run.status == "queued")
            .order_by(m.Run.created_at)
            .limit(settings.max_queue)
        ).all()
        db.commit()
    broker = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
    for identity in queued:
        if broker.llen("celery") >= settings.max_queue:
            break
        if broker.set(f"dispatch:{identity}", "1", nx=True, ex=60):
            try:
                execute_run.apply_async(args=[identity], expires=60)
            except Exception:
                broker.delete(f"dispatch:{identity}")
                raise
