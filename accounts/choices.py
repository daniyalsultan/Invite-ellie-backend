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
