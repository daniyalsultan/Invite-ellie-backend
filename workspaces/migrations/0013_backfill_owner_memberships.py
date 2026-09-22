"""Every existing workspace gets its owner as an active owner member.

This is what keeps behaviour identical when authorisation moves from the
`owner` column to membership. Data only — the recall-server mirror is filled
separately by `reconcile_memberships --apply`, since a migration must not
depend on another service being reachable.
"""

from django.db import migrations


def backfill(apps, schema_editor):
    Workspace = apps.get_model('workspaces', 'Workspace')
    WorkspaceMembership = apps.get_model('workspaces', 'WorkspaceMembership')
    already = set(
        WorkspaceMembership.objects.filter(role='owner', status='active')
        .values_list('workspace_id', 'profile_id')
    )
    WorkspaceMembership.objects.bulk_create([
        WorkspaceMembership(
            workspace_id=workspace.id,
            profile_id=workspace.owner_id,
            role='owner',
            status='active',
            joined_at=workspace.created_at,
        )
        for workspace in Workspace.objects.all().only('id', 'owner_id', 'created_at')
        if (workspace.id, workspace.owner_id) not in already
    ])


def unbackfill(apps, schema_editor):
    Workspace = apps.get_model('workspaces', 'Workspace')
    WorkspaceMembership = apps.get_model('workspaces', 'WorkspaceMembership')
    for workspace in Workspace.objects.all().only('id', 'owner_id'):
        WorkspaceMembership.objects.filter(
            workspace_id=workspace.id, profile_id=workspace.owner_id, role='owner'
        ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('workspaces', '0012_workspace_membership'),
    ]

    operations = [
        migrations.RunPython(backfill, unbackfill),
    ]
