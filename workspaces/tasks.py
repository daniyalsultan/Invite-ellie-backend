# accounts/tasks.py
from celery import shared_task, group
from django.contrib.auth import get_user_model
from accounts.tasks import calculate_user_storage
from accounts.utils import get_user_db_size_bytes
from accounts.models import ProfileStorage
from workspaces.models import Meeting  # adjust import
from django.utils import timezone
from datetime import timedelta
import logging
from accounts.models import Profile
from supabase import create_client
from django.conf import settings

logger = logging.getLogger(__name__)

@shared_task
def trim_old_non_pinned_meetings(user_id: str, keep_days: int = 30):
    cutoff = timezone.now() - timedelta(days=keep_days)
    deleted = Meeting.objects.filter(
        folder__workspace__owner_id=user_id,
        folder__is_pinned=False,
        held_at__lt=cutoff,
    ).delete()[0]

    if deleted:
        logger.info(f"Trimmed {deleted} old non-pinned meetings for user {user_id}")

@shared_task
def nightly_storage_maintenance():
    """Main nightly job - recalc storage + optional auto-trim"""
    user_ids = Profile.objects.values_list('id', flat=True)

    job = group(calculate_user_storage.s(uid) for uid in user_ids)
    result = job.apply_async()
    result.join()

    over_quota_users = ProfileStorage.objects.filter(total_mb__gt=500).values_list('user_id', flat=True)
    if over_quota_users:
        trim_job = group(trim_old_non_pinned_meetings.s(uid) for uid in over_quota_users)
        trim_job.apply_async()

    logger.info("=== NIGHTLY STORAGE MAINTENANCE COMPLETED ===")
    logger.info(f"Users total  : {len(user_ids)}")
    logger.info(f"Over 500 MiB : {len(over_quota_users)} users → auto-trimmed")
    logger.info("All done!")


@shared_task(name='monthly_supabase_orphan_check')
def monthly_supabase_orphan_check():
    """
    Monthly task to detect and report orphaned data in Supabase.
    Currently checks: profiles without matching auth.users entry.

    Can be extended to check storage files, recordings, etc.
    """
    supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)

    logger.info("Starting monthly Supabase orphan check...")

    orphaned_count = 0
    orphaned_ids = []

    try:
        # Step 1: Get all Supabase auth user IDs
        auth_users_response = supabase.auth.admin.list_users()
        auth_user_ids = {user.id for user in auth_users_response if user.id}

        logger.info(f"Found {len(auth_user_ids)} active auth users")

        # Step 2: Get all profile IDs from public.profiles
        profiles_response = supabase.table("profiles").select("id").execute()
        profile_ids = {row["id"] for row in profiles_response.data}

        logger.info(f"Found {len(profile_ids)} profiles in database")

        # Step 3: Find profiles without matching auth user (orphaned)
        orphaned_profile_ids = profile_ids - auth_user_ids

        if orphaned_profile_ids:
            orphaned_count = len(orphaned_profile_ids)
            orphaned_ids = list(orphaned_profile_ids)[:50]  # limit for log

            logger.warning(f"Found {orphaned_count} orphaned profiles (no matching auth.users entry)")

            # Optional: auto-delete them (uncomment if you want automatic cleanup)
            # for pid in orphaned_profile_ids:
            #     supabase.table("profiles").delete().eq("id", pid).execute()
            #     logger.info(f"Auto-deleted orphaned profile: {pid}")

        else:
            logger.info("No orphaned profiles found — all good!")

        # Optional: extend to other checks (storage files, recordings, etc.)
        # Example: check exports bucket (requires listing objects)

    except Exception as e:
        logger.error(f"Orphan check failed: {str(e)}", exc_info=True)
        return {"status": "error", "message": str(e)}

    result = {
        "status": "success",
        "orphaned_profiles_found": orphaned_count,
        "orphaned_profile_ids_sample": orphaned_ids,
        "checked_at": timezone.now().isoformat(),
    }

    logger.info(f"Monthly orphan check complete: {result}")
    return result