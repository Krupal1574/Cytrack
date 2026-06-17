from django.contrib import admin
from .models import Source

@admin.register(Source)
class SourceAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'last_sync_status', 'last_sync_time', 'total_items_ingested')
    list_filter = ('is_active', 'last_sync_status')
    search_fields = ('name', 'error_message')
    readonly_fields = ('last_sync_time', 'last_sync_status', 'error_message', 'total_items_ingested')
