from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('intelligence', '0002_remove_indicatorofcompromise_sources_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CorrelationReport',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('ioc', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='correlation_report',
                    to='intelligence.indicatorofcompromise',
                    db_index=True
                )),
                ('risk_score', models.IntegerField(default=0, help_text='Composite risk score 0–100')),
                ('source_overlap_score', models.IntegerField(default=0, help_text='Score contribution from source overlap (0–30)')),
                ('confidence_score', models.IntegerField(default=0, help_text='Score derived from IOC confidence field (0–25)')),
                ('correlation_score', models.IntegerField(default=0, help_text='Score reflecting actor/CVE relationship depth (0–45)')),
                ('source_count', models.IntegerField(default=0)),
                ('actor_count', models.IntegerField(default=0)),
                ('vulnerability_count', models.IntegerField(default=0)),
                ('pulse_count', models.IntegerField(default=0)),
                ('evidence', models.JSONField(default=list, help_text='Human-readable list of evidence strings explaining the score')),
                ('last_computed', models.DateTimeField(auto_now=True, help_text='When this report was last recomputed')),
            ],
            options={
                'verbose_name': 'Correlation Report',
                'verbose_name_plural': 'Correlation Reports',
                'ordering': ['-risk_score'],
            },
        ),
    ]
