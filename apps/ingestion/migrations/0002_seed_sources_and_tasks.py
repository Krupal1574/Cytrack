from django.db import migrations
import json

def seed_data(apps, schema_editor):
    Source = apps.get_model('ingestion', 'Source')
    IntervalSchedule = apps.get_model('django_celery_beat', 'IntervalSchedule')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')

    # Ensure interval schedule exists
    interval_1hr, _ = IntervalSchedule.objects.get_or_create(every=1, period='hours')
    interval_6hr, _ = IntervalSchedule.objects.get_or_create(every=6, period='hours')
    interval_24hr, _ = IntervalSchedule.objects.get_or_create(every=24, period='hours')

    sources_data = [
        {'name': 'AlienVault OTX', 'task': 'apps.ingestion.tasks.ingest_otx_pulses', 'interval': interval_1hr},
        {'name': 'AbuseIPDB', 'task': 'apps.ingestion.tasks.ingest_abuseipdb_blacklist', 'interval': interval_6hr},
        {'name': 'CISA KEV', 'task': 'apps.ingestion.tasks.ingest_cisa_kev', 'interval': interval_24hr},
        {'name': 'NVD CVE', 'task': 'apps.ingestion.tasks.ingest_nvd_cves', 'interval': interval_1hr},
    ]

    for data in sources_data:
        # Create Source
        source, _ = Source.objects.get_or_create(
            name=data['name'],
            defaults={'is_active': True, 'sync_interval_seconds': data['interval'].every * 3600 if data['interval'].period == 'hours' else 3600}
        )
        
        # Create Periodic Task
        PeriodicTask.objects.get_or_create(
            name=f"Sync {data['name']}",
            defaults={
                'task': data['task'],
                'interval': data['interval'],
                'enabled': True
            }
        )

def reverse_seed(apps, schema_editor):
    Source = apps.get_model('ingestion', 'Source')
    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
    Source.objects.all().delete()
    PeriodicTask.objects.filter(name__startswith='Sync ').delete()

class Migration(migrations.Migration):

    dependencies = [
        ('ingestion', '0001_initial'),
        ('django_celery_beat', '0019_alter_periodictasks_options'), 
    ]

    operations = [
        migrations.RunPython(seed_data, reverse_seed),
    ]
