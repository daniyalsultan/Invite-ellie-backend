from django.db.models import (
    TextChoices
)

class WorkspaceCategoryChoices(TextChoices):
    PROJECT = 'PROJECT', 'Project'
    OFFICE = 'OFFICE', 'Office'
    TEAM = 'TEAM', 'Team'
    OTHER = 'OTHER', 'Other'

class MeetingStatusChoices(TextChoices):
    PENDING = 'PENDING', 'Pending'
    TRANSCRIBING = 'TRANSCRIBING', 'Transcibing'
    SUMMARIZING = 'SUMMARIZING', 'Summarizing'
    COMPLETED = 'COMPLETED', 'Completed'
    FAILED = 'FAILED', 'Failed'

