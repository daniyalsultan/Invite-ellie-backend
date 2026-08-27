# workspaces/filters.py
import django
import django_filters
from django_filters import CharFilter, DateTimeFilter
from .models import Workspace

class WorkspaceFilter(django_filters.FilterSet):
    name = CharFilter(lookup_expr='icontains')
    created_at = DateTimeFilter(lookup_expr='date')

    class Meta:
        model = Workspace
        fields = ['name', 'created_at']

