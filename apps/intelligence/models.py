import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from apps.accounts.models import Organization
from apps.ingestion.models import Source

class TimeStampedModel(models.Model):
    """Abstract base class with created and updated timestamps."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class ThreatActor(TimeStampedModel):
    """Represents a Threat Actor or APT Group."""
    name = models.CharField(max_length=255, unique=True, db_index=True)
    aliases = models.JSONField(default=list, blank=True, help_text=_("List of known aliases"))
    description = models.TextField(blank=True)
    country_of_origin = models.CharField(max_length=100, blank=True)
    target_sectors = models.JSONField(default=list, blank=True)
    first_seen = models.DateField(null=True, blank=True)
    last_seen = models.DateField(null=True, blank=True)
    
    # Custom scoring
    threat_score = models.IntegerField(default=50, help_text=_("0-100 score"))

    class Meta:
        ordering = ['-threat_score', 'name']

    def __str__(self):
        return self.name

class Vulnerability(TimeStampedModel):
    """Represents a Vulnerability (CVE)."""
    cve_id = models.CharField(max_length=50, unique=True, db_index=True)
    description = models.TextField(blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    published_date = models.DateTimeField(null=True, blank=True)
    last_modified_date = models.DateTimeField(null=True, blank=True)
    
    # CISA KEV specific
    is_kev = models.BooleanField(default=False, db_index=True, help_text=_("Known Exploited Vulnerability"))
    kev_added_date = models.DateField(null=True, blank=True)
    kev_due_date = models.DateField(null=True, blank=True)
    kev_action = models.TextField(blank=True)
    
    # NVD CVE specific
    base_score_v3 = models.FloatField(null=True, blank=True, help_text=_("CVSS v3 Base Score"))
    severity_v3 = models.CharField(max_length=20, blank=True, help_text=_("CVSS v3 Severity (e.g. HIGH, CRITICAL)"))
    cvss_v2_score = models.FloatField(null=True, blank=True, help_text=_("CVSS v2 Base Score"))
    vector_string = models.CharField(max_length=100, blank=True, help_text=_("CVSS vector string"))

    # External references: list of {"url": "...", "source": "..."} dicts
    references = models.JSONField(default=list, blank=True, help_text=_("NVD reference URLs"))

    # Affected products: list of CPE strings
    affected_products = models.JSONField(default=list, blank=True, help_text=_("CPE strings for affected products"))


    class Meta:
        ordering = ['-cvss_score', '-published_date']
        verbose_name_plural = "Vulnerabilities"

    def __str__(self):
        return self.cve_id

class IndicatorType(models.TextChoices):
    IPV4 = 'ipv4', _('IPv4 Address')
    IPV6 = 'ipv6', _('IPv6 Address')
    DOMAIN = 'domain', _('Domain Name')
    URL = 'url', _('URL')
    MD5 = 'md5', _('MD5 Hash')
    SHA1 = 'sha1', _('SHA-1 Hash')
    SHA256 = 'sha256', _('SHA-256 Hash')
    EMAIL = 'email', _('Email Address')
    MUTEX = 'mutex', _('Mutex')

class IndicatorOfCompromise(TimeStampedModel):
    """Represents a specific Indicator of Compromise (IOC)."""
    value = models.CharField(max_length=2048, db_index=True)
    type = models.CharField(max_length=20, choices=IndicatorType.choices, db_index=True)
    
    # Context
    description = models.TextField(blank=True)
    confidence = models.IntegerField(default=50, help_text=_("0-100 confidence score"))
    severity = models.CharField(max_length=20, default='low', choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ])
    
    # State
    is_active = models.BooleanField(default=True, db_index=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)

    # Relationships
    threat_actors = models.ManyToManyField(ThreatActor, blank=True, related_name='iocs')
    vulnerabilities = models.ManyToManyField(Vulnerability, blank=True, related_name='iocs')
    
    # Source tracking
    sources_json = models.JSONField(default=list, help_text=_("Legacy list of sources"), blank=True)
    source_nodes = models.ManyToManyField(Source, blank=True, related_name='iocs')

    class Meta:
        ordering = ['-created_at']
        verbose_name = "IOC"
        verbose_name_plural = "IOCs"
        indexes = [
            models.Index(fields=['type', 'value']),
        ]
        unique_together = ('type', 'value')

    def __str__(self):
        return f"{self.type}: {self.value}"

class Report(TimeStampedModel):
    """Generated Intelligence Report."""
    title = models.CharField(max_length=255)
    summary = models.TextField()
    content = models.TextField()
    author = models.CharField(max_length=255, default='CyTrack Auto-Intel')
    published_date = models.DateTimeField(auto_now_add=True)
    
    # Optional multi-tenancy: if linked to an org, it's private. Otherwise it's global.
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='reports')

    class Meta:
        ordering = ['-published_date']

    def __str__(self):
        return self.title

class ThreatPulse(TimeStampedModel):
    """
    Represents a Threat Pulse or Collection (e.g., AlienVault OTX Pulse).
    Groups multiple IOCs together around a central theme or campaign.
    """
    name = models.CharField(max_length=255, db_index=True)
    external_id = models.CharField(max_length=255, unique=True, db_index=True, help_text=_("External ID (e.g., OTX pulse ID)"))
    description = models.TextField(blank=True)
    
    source = models.ForeignKey(Source, on_delete=models.CASCADE, related_name='pulses')
    iocs = models.ManyToManyField(IndicatorOfCompromise, blank=True, related_name='pulses')
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return self.name
