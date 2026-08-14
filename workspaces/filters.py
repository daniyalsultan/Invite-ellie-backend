# workspaces/filters.py
import django
import django_filters
from django_filters import CharFilter, DateTimeFilter
from .models import Workspace, Meeting
from .choices import MeetingStatusChoices

class WorkspaceFilter(django_filters.FilterSet):
    name = CharFilter(lookup_expr='icontains')
    created_at = DateTimeFilter(lookup_expr='date')

    class Meta:
        model = Workspace
        fields = ['name', 'created_at']


class MeetingFilter(django_filters.FilterSet):
    title = CharFilter(lookup_expr='icontains')
    status = django_filters.ChoiceFilter(choices=MeetingStatusChoices.choices)
    workspace = django_filters.UUIDFilter(field_name='workspace__id')
    created_at__gte = DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_at__lte = DateTimeFilter(field_name='created_at', lookup_expr='lte')
    search = CharFilter(method='filter_search')
    calendar_event_id = CharFilter(lookup_expr='icontains')
    bot_id = CharFilter(lookup_expr='icontains')
    transcription_id = CharFilter(lookup_expr='icontains')
    no_workspace = django_filters.BooleanFilter(method='filter_no_workspace', label='No Workspace')

    class Meta:
        model = Meeting
        fields = ['title', 'status', 'workspace', 'created_at__gte', 'created_at__lte', 'search', 'calendar_event_id', 'bot_id', 'transcription_id']

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            django.db.models.Q(title__icontains=value) |
            django.db.models.Q(transcript__icontains=value) |
            django.db.models.Q(summary__icontains=value)
        )

    def filter_no_workspace(self, queryset, name, value):
        if value is True:
            return queryset.filter(workspace__isnull=True)
        elif value is False:
            return queryset.filter(workspace__isnull=False)
        return queryset
