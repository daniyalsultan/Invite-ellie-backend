import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0017_add_auto_join_meetings'),
        ('workspaces', '0011_drop_unused_meeting_model'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='workspace',
            name='unique_workspace_per_user',
        ),
        migrations.CreateModel(
            name='WorkspaceMembership',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('role', models.CharField(choices=[('owner', 'Owner'), ('member', 'Member')], default='member', max_length=16)),
                ('status', models.CharField(choices=[('active', 'Active'), ('invited', 'Invited'), ('removed', 'Removed')], default='active', max_length=16)),
                ('invited_email', models.EmailField(blank=True, default='', max_length=254)),
                ('invite_token', models.CharField(blank=True, max_length=64, null=True, unique=True)),
                ('invite_expires_at', models.DateTimeField(blank=True, null=True)),
                ('joined_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('invited_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='accounts.profile')),
                ('profile', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='workspace_memberships', to='accounts.profile')),
                ('workspace', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='memberships', to='workspaces.workspace')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['profile', 'status'], name='workspaces__profile_9843cf_idx'),
                    models.Index(fields=['workspace', 'status'], name='workspaces__workspa_205f2f_idx'),
                ],
                'constraints': [
                    models.UniqueConstraint(condition=models.Q(('status__in', ['active', 'invited'])), fields=('workspace', 'profile'), name='unique_live_membership_per_profile'),
                ],
            },
        ),
    ]
