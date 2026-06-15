# CyTrack — Production Makefile
# ================================
# Common development and deployment commands.
# Usage: make <target>

.PHONY: help install dev test lint format migrate shell docker-up docker-down

help:
	@echo "CyTrack Development Commands"
	@echo "============================"
	@echo "  make install     Install Python dependencies"
	@echo "  make dev         Start development server"
	@echo "  make test        Run test suite with coverage"
	@echo "  make lint        Run linting checks"
	@echo "  make format      Format code with Black + isort"
	@echo "  make migrate     Run database migrations"
	@echo "  make shell       Open Django shell"
	@echo "  make docker-up   Start all Docker services"
	@echo "  make docker-down Stop all Docker services"

install:
	pip install -r requirements.txt

dev:
	python manage.py runserver

test:
	pytest

lint:
	flake8 apps/ cyber/ --max-line-length=100 --exclude=migrations
	black --check .
	isort --check-only .

format:
	black .
	isort .

migrate:
	python manage.py makemigrations
	python manage.py migrate

shell:
	python manage.py shell_plus 2>/dev/null || python manage.py shell

superuser:
	python manage.py createsuperuser

collectstatic:
	python manage.py collectstatic --noinput

celery-worker:
	celery -A cyber worker --loglevel=info

celery-beat:
	celery -A cyber beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f web

docker-build:
	docker compose build
