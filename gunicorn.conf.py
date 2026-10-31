# Gunicorn settings for CampusFix (picked up automatically when you run:  gunicorn app:app -c gunicorn.conf.py)
import os

worker_class = "gthread"
# OTP / reset-token state is in the database, so more workers are possible - but only help on an instance
# with 1+ CPU (see README, "Scaling"). On a small instance keep 1 worker and use threads.
workers = int(os.getenv("GUNICORN_WORKERS", "1"))
threads = int(os.getenv("GUNICORN_THREADS", "8"))          # keep <= DB_POOL_SIZE (default 10)
timeout = int(os.getenv("GUNICORN_TIMEOUT", "60"))
graceful_timeout = 30                                       # on deploy: let running requests finish
keepalive = 5
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
if os.path.isdir("/dev/shm"):
    worker_tmp_dir = "/dev/shm"                             # heartbeat file in RAM (avoids false worker timeouts)
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
