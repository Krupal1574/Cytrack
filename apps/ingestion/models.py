from django.db import models
from django.utils.translation import gettext_lazy as _

class SourceStatus(models.TextChoices):
    IDLE = 'idle', _('Idle')
    RUNNING = 'running', _('Running')
    SUCCESS = 'success', _('Success')
    FAILED = 'failed', _('Failed')

class Source(models.Model):
    """
    Represents an external Threat Intelligence integration source.
    """
    name = models.CharField(max_length=100, unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    
    # Sync tracking
    last_sync_time = models.DateTimeField(null=True, blank=True)
    last_sync_status = models.CharField(
        max_length=20, 
        choices=SourceStatus.choices, 
        default=SourceStatus.IDLE
    )
    error_message = models.TextField(blank=True)
    
    # Configuration
    sync_interval_seconds = models.IntegerField(default=3600, help_text=_("Desired sync interval in seconds"))
    
    # Statistics
    total_items_ingested = models.BigIntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name
