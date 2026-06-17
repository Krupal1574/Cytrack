from django.db import migrations


def seed_periodic_tasks(apps, schema_editor):
    IntervalSchedule = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=6,
        period='hours',
    )

    PeriodicTask.objects.get_or_create(
        name='Rebuild All Correlation Reports (6h)',
        defaults={
            'task': 'apps.investigation.tasks.rebuild_all_correlations',
            'interval': schedule,
            'enabled': True,
        }
    )


def remove_periodic_tasks(apps, schema_editor):
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    PeriodicTask.objects.filter(
        name='Rebuild All Correlation Reports (6h)'
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('investigation', '0001_initial'),
        ('django_celery_beat', '0019_alter_periodictasks_options'),
    ]

    operations = [
        migrations.RunPython(seed_periodic_tasks, remove_periodic_tasks),
    ]
