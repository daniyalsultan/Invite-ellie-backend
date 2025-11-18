import django_filters
from .models import Notification, ActivityLog
from .choices import NotificationType, ActivityLogTypes
from django.db.models import Q

class NotificationFilter(django_filters.FilterSet):
    notify_type = django_filters.ChoiceFilter(choices=NotificationType.choices)
    seen = django_filters.BooleanFilter()
    created_at_after = django_filters.DateFilter(field_name='created_at', lookup_expr='gte')
    created_at_before = django_filters.DateFilter(field_name='created_at', lookup_expr='lte')
    search = django_filters.CharFilter(field_name='message', lookup_expr='icontains')

    class Meta:
        model = Notification
        fields = ['notify_type', 'seen', 'created_at_after', 'created_at_before', 'search']


class ActivityLogFilter(django_filters.FilterSet):
    activity_type = django_filters.ChoiceFilter(choices=ActivityLogTypes.choices)
    timestamp_after = django_filters.DateFilter(field_name='timestamp', lookup_expr='gte')
    timestamp_before = django_filters.DateFilter(field_name='timestamp', lookup_expr='lte')
    search = django_filters.CharFilter(method='filter_search')

    class Meta:
        model = ActivityLog
        fields = ['activity_type', 'timestamp_after', 'timestamp_before']

    def filter_search(self, queryset, name, value):
        return queryset.filter(
            Q(description__icontains=value) |
            Q(activity_type__icontains=value)
        )