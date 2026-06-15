"""
CyTrack Django Settings — Production-Ready
==========================================
All secrets are loaded from environment variables.
Never hardcode credentials in this file.

Environment variable loading order:
  1. System environment variables (highest priority)
  2. .env file at project root

Usage:
  Development: DJANGO_ENV=development python manage.py runserver
  Production:  DJANGO_ENV=production gunicorn cyber.wsgi
"""

import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Base Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file — support both .env/ directory (legacy) and .env file
_env_file = BASE_DIR / '.env' / '.env'
if _env_file.exists():
    load_dotenv(_env_file)
else:
    load_dotenv(BASE_DIR / '.env')

# ---------------------------------------------------------------------------
# Environment Detection
# ---------------------------------------------------------------------------
DJANGO_ENV = os.environ.get('DJANGO_ENV', 'development')
IS_PRODUCTION = DJANGO_ENV == 'production'

# ---------------------------------------------------------------------------
# SECURITY — All loaded from environment variables
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get(
    'SECRET_KEY',
    # Default is only used locally when .env is missing — never in production
    'change-me-in-production-this-is-only-for-dev-setup'
)

DEBUG = os.environ.get('DEBUG', 'True' if not IS_PRODUCTION else 'False') == 'True'

ALLOWED_HOSTS = os.environ.get(
    'ALLOWED_HOSTS', 'localhost,127.0.0.1'
).split(',')

# ---------------------------------------------------------------------------
# Application Definition
# ---------------------------------------------------------------------------
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    # REST framework
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'drf_spectacular',
    # Filtering
    'django_filters',
    # CORS
    'corsheaders',
    # Celery task results
    'django_celery_results',
    'django_celery_beat',
    # Channels (WebSocket)
    'channels',
]

LOCAL_APPS = [
    'apps.core.apps.CoreConfig',
    'apps.accounts.apps.AccountsConfig',
    'apps.intelligence.apps.IntelligenceConfig',
    'apps.ingestion.apps.IngestionConfig',
    'apps.alerts.apps.AlertsConfig',
    # Legacy dashboard app (migrated in Phase 1, replaced in Phase 4)
    'dashboard.apps.DashboardConfig',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # WhiteNoise — serve static files efficiently in production
    'whitenoise.middleware.WhiteNoiseMiddleware',
    # CORS — must be before CommonMiddleware
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'cyber.urls'

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# ASGI / WSGI
# ---------------------------------------------------------------------------
WSGI_APPLICATION = 'cyber.wsgi.application'
ASGI_APPLICATION = 'cyber.asgi.application'

# ---------------------------------------------------------------------------
# Database — loaded from environment variables
# ---------------------------------------------------------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'cytrackdb'),
        'USER': os.environ.get('DB_USER', 'cytrack'),
        'PASSWORD': os.environ.get('DB_PASSWORD', ''),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'OPTIONS': {
            'connect_timeout': 10,
        },
        'CONN_MAX_AGE': 60,  # Persistent connections (60s)
    }
}

# ---------------------------------------------------------------------------
# Custom User Model
# ---------------------------------------------------------------------------
AUTH_USER_MODEL = 'accounts.User'

# ---------------------------------------------------------------------------
# Password Validation
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ---------------------------------------------------------------------------
# Internationalization
# ---------------------------------------------------------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static & Media Files
# ---------------------------------------------------------------------------
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

# WhiteNoise compression
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ---------------------------------------------------------------------------
# Default Primary Key
# ---------------------------------------------------------------------------
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ---------------------------------------------------------------------------
# Redis — Cache + Channel Layer + Celery Broker
# ---------------------------------------------------------------------------
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': REDIS_URL,
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'CONNECTION_POOL_KWARGS': {'max_connections': 20},
        },
        'KEY_PREFIX': 'cytrack',
        'TIMEOUT': 300,  # 5 minutes default TTL
    }
}

# Session stored in Redis for horizontal scaling
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# ---------------------------------------------------------------------------
# Django Channels — WebSocket
# ---------------------------------------------------------------------------
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [REDIS_URL],
            'capacity': 1500,
            'expiry': 10,
        },
    },
}

# ---------------------------------------------------------------------------
# Celery — Task Queue
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', REDIS_URL)
CELERY_RESULT_BACKEND = 'django-db'  # Use django-celery-results
CELERY_CACHE_BACKEND = 'default'

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True

# Task routing — separate queues for different priorities
CELERY_TASK_ROUTES = {
    'apps.ingestion.tasks.*': {'queue': 'ingestion'},
    'apps.scoring.tasks.*': {'queue': 'scoring'},
    'apps.alerts.tasks.*': {'queue': 'alerts'},
}

CELERY_TASK_ALWAYS_EAGER = False  # Set True in tests to run tasks synchronously

# Beat schedule — populated in apps/ingestion after app creation
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# ---------------------------------------------------------------------------
# REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 25,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '20/hour',
        'user': '1000/hour',
    },
    'EXCEPTION_HANDLER': 'apps.core.exceptions.cytrack_exception_handler',
}

# ---------------------------------------------------------------------------
# JWT Settings
# ---------------------------------------------------------------------------
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

# ---------------------------------------------------------------------------
# drf-spectacular (OpenAPI docs)
# ---------------------------------------------------------------------------
SPECTACULAR_SETTINGS = {
    'TITLE': 'CyTrack API',
    'DESCRIPTION': 'Cyber Threat Intelligence Platform REST API',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'TAGS': [
        {'name': 'auth', 'description': 'Authentication'},
        {'name': 'iocs', 'description': 'Indicators of Compromise'},
        {'name': 'pulses', 'description': 'Threat Pulses'},
        {'name': 'cves', 'description': 'CVE Vulnerabilities'},
        {'name': 'actors', 'description': 'Threat Actors'},
        {'name': 'alerts', 'description': 'Alerts'},
        {'name': 'stats', 'description': 'Dashboard Statistics'},
    ],
}

# ---------------------------------------------------------------------------
# CORS — Cross-Origin Resource Sharing
# ---------------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = os.environ.get(
    'CORS_ALLOWED_ORIGINS',
    'http://localhost:3000,http://localhost:8000'
).split(',')

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = [
    'accept', 'accept-encoding', 'authorization',
    'content-type', 'dnt', 'origin', 'user-agent',
    'x-csrftoken', 'x-requested-with', 'x-api-key',
]

# ---------------------------------------------------------------------------
# External API Keys — loaded from environment variables
# ---------------------------------------------------------------------------
OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')

# ---------------------------------------------------------------------------
# Security Headers (active in production)
# ---------------------------------------------------------------------------
if IS_PRODUCTION:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
else:
    # Development — relaxed security
    SECURE_SSL_REDIRECT = False
    X_FRAME_OPTIONS = 'SAMEORIGIN'

# ---------------------------------------------------------------------------
# Logging — structured logging to console + file
# ---------------------------------------------------------------------------
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {asctime} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOGS_DIR / 'cytrack.log',
            'maxBytes': 10 * 1024 * 1024,  # 10 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'celery_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOGS_DIR / 'celery.log',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': True,
        },
        'apps': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'celery': {
            'handlers': ['console', 'celery_file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
    },
}
