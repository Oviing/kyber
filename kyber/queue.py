"""RQ queue helpers. Falls back to synchronous execution when Redis is unavailable (tests)."""
from kyber.config import settings

QUEUE_NAME = "kyber"


def get_queue():
    try:
        import redis
        from rq import Queue

        conn = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2)
        conn.ping()
        return Queue(QUEUE_NAME, connection=conn)
    except Exception:
        return None


def enqueue_scan(scan_id: str) -> str:
    q = get_queue()
    if q is None:
        # Synchronous fallback (dev/test): run inline.
        from kyber.worker.jobs import run_scan

        run_scan(scan_id)
        return "inline"
    job = q.enqueue("kyber.worker.jobs.run_scan", scan_id, job_timeout=1800)
    return job.id
