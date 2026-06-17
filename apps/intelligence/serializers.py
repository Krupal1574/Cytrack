from rest_framework import serializers
from .models import IndicatorOfCompromise, ThreatActor, Vulnerability
from apps.ingestion.models import Source

class SourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Source
        fields = ['id', 'name', 'is_active', 'last_sync_time', 'last_sync_status', 'error_message', 'total_items_ingested']

class IndicatorOfCompromiseSerializer(serializers.ModelSerializer):
    score = serializers.SerializerMethodField()
    source_names = serializers.StringRelatedField(many=True, read_only=True, source='source_nodes')

    class Meta:
        model = IndicatorOfCompromise
        fields = [
            'id', 'value', 'type', 'description', 'confidence', 
            'severity', 'is_active', 'first_seen', 'last_seen', 
            'source_names', 'score'
        ]

    def get_score(self, obj):
        from .scoring import ThreatScoringEngine
        return ThreatScoringEngine.calculate_ioc_score(obj)

class ThreatActorSerializer(serializers.ModelSerializer):
    iocs = IndicatorOfCompromiseSerializer(many=True, read_only=True)

    class Meta:
        model = ThreatActor
        fields = [
            'id', 'name', 'aliases', 'description', 'country_of_origin',
            'target_sectors', 'first_seen', 'last_seen', 'threat_score',
            'iocs'
        ]

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'cve_id', 'description', 'cvss_score', 'published_date',
            'is_kev', 'kev_added_date', 'kev_due_date', 'kev_action',
            'base_score_v3', 'severity_v3'
        ]
