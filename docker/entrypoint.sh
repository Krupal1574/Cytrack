#!/bin/bash
# ============================================================
# CyTrack Docker Entrypoint
# ============================================================
set -e

# Wait for PostgreSQL to be ready
echo "[entrypoint] Waiting for PostgreSQL..."
until python -c "
import django, os, sys
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber.settings')
django.setup()
from django.db import connection
connection.ensure_connection()
print('PostgreSQL is ready!')
"; do
    echo "[entrypoint] PostgreSQL unavailable — retrying in 2s..."
    sleep 2
done

case "$1" in
    "web")
        echo "[entrypoint] Running migrations..."
        python manage.py migrate --noinput

        echo "[entrypoint] Collecting static files..."
        python manage.py collectstatic --noinput --clear

        echo "[entrypoint] Starting Uvicorn (ASGI)..."
        exec uvicorn cyber.asgi:application \
            --host 0.0.0.0 \
            --port "${PORT:-8000}" \
            --workers "${UVICORN_WORKERS:-2}" \
            --log-level info
        ;;

    "worker")
        echo "[entrypoint] Starting Celery worker..."
        exec celery -A cyber worker \
            --loglevel=info \
            --queues=ingestion,scoring,alerts,celery \
            --concurrency=4
        ;;

    "beat")
        echo "[entrypoint] Starting Celery Beat scheduler..."
        exec celery -A cyber beat \
            --loglevel=info \
            --scheduler django_celery_beat.schedulers:DatabaseScheduler
        ;;

    "flower")
        echo "[entrypoint] Starting Flower monitoring..."
        exec celery -A cyber flower \
            --port=5555
        ;;

    *)
        # Allow running arbitrary commands (e.g., for debugging)
        exec "$@"
        ;;
esac
