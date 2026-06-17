from django.contrib import admin
from .models import CorrelationReport


@admin.register(CorrelationReport)
class CorrelationReportAdmin(admin.ModelAdmin):
    list_display = (
        'ioc', 'risk_score', 'source_overlap_score', 'confidence_score',
        'correlation_score', 'source_count', 'actor_count',
        'vulnerability_count', 'last_computed'
    )
    list_filter = ('ioc__severity', 'ioc__type')
    search_fields = ('ioc__value',)
    readonly_fields = (
        'ioc', 'risk_score', 'source_overlap_score', 'confidence_score',
        'correlation_score', 'source_count', 'actor_count', 'vulnerability_count',
        'pulse_count', 'evidence', 'last_computed'
    )
    ordering = ('-risk_score',)
