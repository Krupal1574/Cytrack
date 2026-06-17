from django.apps import AppConfig


class InvestigationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.investigation'
    verbose_name = 'Investigation'

    def ready(self):
        import apps.investigation.signals  # noqa: F401 — register signal handlers
