from rest_framework import serializers
from django.utils import timezone

from apps.intelligence.models import IndicatorOfCompromise, ThreatActor, Vulnerability, ThreatPulse
from apps.ingestion.models import Source
from apps.investigation.models import CorrelationReport


class InvestigationSourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Source
        fields = ['id', 'name', 'last_sync_time', 'last_sync_status']


class InvestigationVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = ['id', 'cve_id', 'description', 'cvss_score', 'is_kev', 'kev_due_date', 'severity_v3']


class InvestigationActorSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatActor
        fields = ['id', 'name', 'country_of_origin', 'threat_score', 'target_sectors']


class InvestigationPulseSerializer(serializers.ModelSerializer):
    source_name = serializers.StringRelatedField(source='source')

    class Meta:
        model = ThreatPulse
        fields = ['id', 'name', 'external_id', 'description', 'source_name']


class InvestigationIOCSerializer(serializers.ModelSerializer):
    class Meta:
        model = IndicatorOfCompromise
        fields = ['id', 'value', 'type', 'severity', 'confidence', 'first_seen', 'last_seen', 'is_active']


class CorrelationReportSerializer(serializers.ModelSerializer):
    """
    Serializer for the cached CorrelationReport model.
    Includes cache metadata (age, last computed).
    """
    ioc = InvestigationIOCSerializer(read_only=True)
    sources = serializers.SerializerMethodField()
    related_vulnerabilities = serializers.SerializerMethodField()
    related_threat_actors = serializers.SerializerMethodField()
    pulses = serializers.SerializerMethodField()
    cache_age_seconds = serializers.SerializerMethodField()
    last_correlation_timestamp = serializers.DateTimeField(source='last_computed', read_only=True)
    is_live = serializers.SerializerMethodField()

    class Meta:
        model = CorrelationReport
        fields = [
            'ioc',
            'risk_score',
            'source_overlap_score',
            'confidence_score',
            'correlation_score',
            'source_count',
            'actor_count',
            'vulnerability_count',
            'pulse_count',
            'evidence',
            'sources',
            'related_vulnerabilities',
            'related_threat_actors',
            'pulses',
            'cache_age_seconds',
            'last_correlation_timestamp',
            'is_live',
        ]

    def get_sources(self, obj):
        sources = obj.ioc.source_nodes.all()
        return InvestigationSourceSerializer(sources, many=True).data

    def get_related_vulnerabilities(self, obj):
        vulns = obj.ioc.vulnerabilities.all()
        return InvestigationVulnerabilitySerializer(vulns, many=True).data

    def get_related_threat_actors(self, obj):
        actors = obj.ioc.threat_actors.all()
        return InvestigationActorSerializer(actors, many=True).data

    def get_pulses(self, obj):
        pulses = obj.ioc.pulses.all()
        return InvestigationPulseSerializer(pulses, many=True).data

    def get_cache_age_seconds(self, obj):
        delta = timezone.now() - obj.last_computed
        return int(delta.total_seconds())

    def get_is_live(self, obj):
        return False


class LiveCorrelationSerializer(serializers.Serializer):
    """
    Serializer for live (non-cached) correlation results.
    Accepts a raw dict produced by CorrelationService.compute().
    """
    ioc = InvestigationIOCSerializer(read_only=True)
    risk_score = serializers.IntegerField()
    source_overlap_score = serializers.IntegerField()
    confidence_score = serializers.IntegerField()
    correlation_score = serializers.IntegerField()
    source_count = serializers.IntegerField()
    actor_count = serializers.IntegerField()
    vulnerability_count = serializers.IntegerField()
    pulse_count = serializers.IntegerField()
    evidence = serializers.ListField(child=serializers.CharField())
    sources = InvestigationSourceSerializer(many=True)
    related_vulnerabilities = InvestigationVulnerabilitySerializer(many=True, source='vulnerabilities')
    related_threat_actors = InvestigationActorSerializer(many=True, source='actors')
    pulses = InvestigationPulseSerializer(many=True)
    cache_age_seconds = serializers.SerializerMethodField()
    last_correlation_timestamp = serializers.SerializerMethodField()
    is_live = serializers.SerializerMethodField()

    def get_cache_age_seconds(self, obj):
        return 0  # Live computation has zero cache age

    def get_last_correlation_timestamp(self, obj):
        return timezone.now().isoformat()

    def get_is_live(self, obj):
        return True
