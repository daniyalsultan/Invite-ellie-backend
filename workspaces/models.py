import uuid
from django.db.models import (
    Model,
    UUIDField,
    ForeignKey,
    CharField,
    DateTimeField,
    CASCADE,
    URLField,
    TextField,
    Index,
)
from django.contrib.postgres.fields import ArrayField
from accounts.models import Profile
from workspaces.choices import MeetingStatusChoices, WorkspaceCategoryChoices

class Workspace(Model):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = ForeignKey(Profile, on_delete=CASCADE, related_name='workspaces')
    name = CharField(max_length=255)
    category = CharField(choices=WorkspaceCategoryChoices.choices, max_length=255, blank=True)
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    class Meta:
        managed = True

    def __str__(self):
        return self.name


class Folder(Model):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    workspace = ForeignKey(Workspace, on_delete=CASCADE, related_name='folders')
    name = CharField(max_length=255)
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    class Meta:
        managed = True

    def __str__(self):
        return f"{self.workspace.name} > {self.name}"


class Meeting(Model):
    id = UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    folder = ForeignKey(Folder, on_delete=CASCADE, related_name='meetings')
    title = CharField(max_length=255)
    status = CharField(max_length=20, choices=MeetingStatusChoices.choices, default=MeetingStatusChoices.PENDING)
    audio_url = URLField(blank=True, null=True)
    transcript = TextField(blank=True, null=True)
    summary = TextField(blank=True, null=True)
    highlights = ArrayField(TextField(), blank=True, null=True)
    action_items = ArrayField(TextField(), blank=True, null=True)
    created_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

    class Meta:
        managed = True
        indexes = [
            Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.title