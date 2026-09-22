"""Compare workspace membership with recall-server's mirror, and repair it.

The backend is the source of truth; recall-server authorises meeting access
from a mirror of each workspace's active members. Every change is written
through, and a failed write-through rolls the change back, so the two should
always agree. This command proves it, and fixes the cases write-through can't
guarantee: a commit that failed after the push, a change made outside the app,
or a push that was allowed to fail (email confirmation, account deletion).

Run with no arguments to report. Nothing is written without --apply, which
re-sends each affected workspace's complete member set.
"""

from django.core.management.base import BaseCommand

from workspaces.membership_sync import discrepancy_total, find_discrepancies, push_workspace_members


class Command(BaseCommand):
    help = "Report (and with --apply, repair) differences between workspace membership and recall-server's mirror"

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Repair the mirror (default is report only)')

    def handle(self, *args, **options):
        found = find_discrepancies()
        counts = found['counts']
        self.stdout.write(f"Active memberships: {counts['backend_active']}   Mirror rows: {counts['mirror']}")
        for label, key in (('Missing from mirror', 'missing'), ('Extra in mirror (grants access)', 'extra')):
            self.stdout.write(f'{label}: {len(found[key])}')
            for workspace_id, user_id in found[key]:
                self.stdout.write(f'  workspace {workspace_id}  user {user_id}')
        self.stdout.write(f"Role mismatches: {len(found['role_mismatch'])}")
        for (workspace_id, user_id), mirror_role, our_role in found['role_mismatch']:
            self.stdout.write(f'  workspace {workspace_id}  user {user_id}  mirror={mirror_role} backend={our_role}')
        self.stdout.write(f"Workspaces with no active owner: {len(found['ownerless_workspaces'])}")
        for workspace_id in found['ownerless_workspaces']:
            self.stdout.write(f'  workspace {workspace_id}')

        total = discrepancy_total(found)
        self.stdout.write(f'Discrepancies: {total}')
        if not options['apply'] or total == 0:
            if total and not options['apply']:
                self.stdout.write('Report only. Re-run with --apply to repair the mirror.')
            return

        # Ownerless workspaces need a person to decide who owns them; the
        # mirror can't fix that. Everything else is fixed by re-sending sets.
        affected = {w for w, _ in found['missing']} | {w for w, _ in found['extra']} | {w for (w, _), _, _ in found['role_mismatch']}
        for workspace_id in sorted(affected):
            result = push_workspace_members(workspace_id)
            self.stdout.write(f'  repaired {workspace_id}: {result}')

        after = find_discrepancies()
        self.stdout.write(f'Discrepancies after repair: {discrepancy_total(after)}')
