from django.db.models import (
    TextChoices
)

class AudienceChoices(TextChoices):
    COMPANY = 'COMPANY', 'Company'
    PERSONAL = 'PERSONAL', 'Personal'

class PurposeChoices(TextChoices):
    TEAM_MEETINGS = 'TEAM_MEETINGS', 'Internal team meetings'
    SALES_CALLS = 'SALES_CALLS', 'Client or sales calls'
    TRAINING = 'TRAINING', 'Workshops or training'
    BRAINSTORMING = 'BRAINSTORMING', 'Brainstorming sessions'

class NotificationType(TextChoices):
    WARNING = 'WARNING', 'Warning'
    SUCCESS = 'SUCCESS', 'Success'
    DANGER = 'DANGER', 'Danger'

class ActivityLogTypes(TextChoices):
    LOGIN_SUCCESS = 'LOGIN_SUCCESS', 'Login Successful'
    LOGIN_FAILED = 'LOGIN_FAILED', 'Login Failed'
    PROFILE_UPDATE = 'PROFILE_UPDATE', 'Profile Updated'
    PASSWORD_CHANGED = 'PASSWORD_CHANGED', 'Password changed'