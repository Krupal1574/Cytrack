"""Accounts app signals — audit logging, post-save hooks."""
import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)
User = get_user_model()


@receiver(post_save, sender=User)
def log_user_creation(sender, instance, created, **kwargs):
    """Log new user registrations for audit trail."""
    if created:
        logger.info(
            'New user created: %s (role=%s, org=%s)',
            instance.email,
            instance.role,
            instance.organization,
        )
