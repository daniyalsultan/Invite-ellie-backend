"""Per-workspace recording retention.

Nullable on purpose: NULL means the workspace has not set a period and the
recording user's own profile decides, which is exactly how every existing
workspace behaved before this column existed. No backfill, because writing
30 into every row would turn an inherited default into an explicit choice
nobody made, and the two are different things the moment someone changes
their profile setting.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('workspaces', '0013_backfill_owner_memberships'),
    ]

    operations = [
        migrations.AddField(
            model_name='workspace',
            name='recording_retention_days',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
