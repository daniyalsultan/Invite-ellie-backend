import uuid
from django.db.models import (
    Model, UUIDField, ForeignKey, CharField, DateTimeField, DurationField,
    CASCADE, URLField, TextField, Index, IntegerField, BooleanField, UniqueConstraint
)
from django.contrib.postgres.fields import ArrayField
from accounts.models import Profile
from workspaces.choices import WorkspaceCategoryChoices

class Workspace(Model):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = ForeignKey(Profile, on_delete=CASCADE, related_name='workspaces')
    name = CharField(max_length=255)
    category = CharField(choices=WorkspaceCategoryChoices.choices, max_length=255, blank=True, null=True)
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    class Meta:
        managed = True
        constraints = [
            UniqueConstraint(
                fields=['owner', 'name'],
                name='unique_workspace_per_user'
            )
        ]

    def __str__(self):
        return self.name

