from django.db.models import (
    TextChoices
)

class WorkspaceCategoryChoices(TextChoices):
    PROJECT = 'PROJECT', 'Project'
    OFFICE = 'OFFICE', 'Office'
    TEAM = 'TEAM', 'Team'
    OTHER = 'OTHER', 'Other'

