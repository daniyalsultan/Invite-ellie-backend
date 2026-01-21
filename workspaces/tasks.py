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
