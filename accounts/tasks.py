from accounts.utils import delete_stripe_pii, pseudonymize_audit_logs
from .models import ActivityLog, DeletionAuditLog, Notification, ProfileStorage, Profile
from .utils import anonymize_user_id, delete_supabase_user, get_user_db_size_bytes
from supabase import create_client
import logging
from decouple import config
from django.utils import timezone
from celery import shared_task, signals
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
import stripe
from workspaces.models import Workspace

logger = logging.getLogger(__name__)
supabase = create_client(config("SUPABASE_URL"), config("SUPABASE_ANON_KEY"))


@signals.task_failure.connect
def celery_task_failure_handler(sender=None, task_id=None, exception=None,
                               traceback=None, einfo=None, **kwargs):
    """
    Automatically sends email when ANY Celery task fails
    """
    task_name = sender.name if sender else "unknown"
    args = kwargs.get('args', [])
    kwargs_dict = kwargs.get('kwargs', {})

    subject = f"Celery Task Failed: {task_name}"
    user_id = "N/A"
    if args:
        user_id = str(args[0])[:8] if len(args) > 0 else "N/A"
    elif 'user_id' in kwargs_dict:
        user_id = str(kwargs_dict['user_id'])[:8]

    body = f"""
CELERY TASK FAILED

Task:       {task_name}
Task ID:    {task_id}
User ID:    {user_id}
Time:       {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}

Exception:
{exception.__class__.__name__}: {str(exception)}

Traceback:
{''.join(traceback.format_tb(einfo.tb)).strip()}

Full args: {args}
Full kwargs: {kwargs_dict}
"""
    try:
        recipients = [email for name, email in getattr(settings, "ADMINS", [])]
        if not recipients:
            logger.warning("No ADMINS configured in settings – failure email not sent")
            return

        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipients,
            fail_silently=False,
        )
        logger.info(f"Failure email sent for task {task_name}")
    except Exception as mail_error:
        logger.error(f"Failed to send failure email: {mail_error}")


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def calculate_user_storage(self, user_id: int, include_supabase: bool = True):
    try:
        db_stats = get_user_db_size_bytes(user_id)

        supabase_bytes = 0
        if include_supabase:
            try:
                files = supabase.storage.from_("meetings").list(f"user_{user_id}/")
                supabase_bytes = sum(f.get('size', 0) for f in files)
            except Exception as e:
                logger.warning(f"Supabase fetch failed: {e}")

        total_bytes = db_stats['total_bytes'] + supabase_bytes
        total_mb = round(total_bytes / (1024 * 1024), 2)

        storage, _ = ProfileStorage.objects.update_or_create(
            user_id=user_id,
            defaults={
                'total_bytes': total_bytes,
                'total_mb': total_mb,
                'breakdown': {
                    **db_stats['breakdown'],
                    'supabase': supabase_bytes
                },
                'supabase_bytes': supabase_bytes,
            }
        )

        return {
            'user_id': user_id,
            'total_mb': total_mb,
            'breakdown': db_stats['breakdown'],
            'supabase_mb': round(supabase_bytes / (1024*1024), 2),
        }

    except Exception as exc:
        logger.exception("Storage calc failed")
        self.retry(exc=exc)


@shared_task
def check_deletion_grace_periods():
    """Periodic task to check expired grace periods, perform deletions, and send emails."""
    now = timezone.now()
    profiles = Profile.objects.filter(
        is_active=True,
        deletion_completed_at__isnull=True,
        deletion_type='GRACE_PERIOD'
    ).exclude(legal_hold=True)

    for profile in profiles:
        # Check if grace period has elapsed
        if (now - profile.deletion_requested_at) >= timedelta(days=7):
            # Perform deletion
            perform_deletion.delay(profile.id)
        else:
            # Send reminder emails on day 3 and day 6
            days_elapsed = (now - profile.deletion_requested_at).days
            if days_elapsed in [3, 6]:
                send_mail(
                    f'Account Deletion Reminder - {7 - days_elapsed} Days Left',
                    f'Your account deletion is scheduled in {7 - days_elapsed} days. To cancel, contact support.',
                    settings.DEFAULT_FROM_EMAIL,
                    [profile.email],
                )

    return f"check_deletion_grace_periods : Checked {profiles.count()} profiles"



@shared_task
def perform_deletion(profile_id, grace_period_days=0):
    try:
        profile = Profile.objects.get(id=profile_id)
    except Profile.DoesNotExist:
        return "Profile not found"

    # re-check grace period
    if grace_period_days > 0:
        days_elapsed = (timezone.now() - profile.deletion_requested_at).days
        if days_elapsed < grace_period_days:
            return f"Grace period not expired ({days_elapsed}/{grace_period_days} days)"

    if profile.legal_hold:
        return "Blocked by legal hold"
    
    # Anonymize ActivityLog
    ActivityLog.objects.filter(profile=profile).update(
        profile_id=anonymize_user_id(str(profile.id)),
        description="[User deleted - data anonymized]",
        meta_data={}  # Clear any personal data
    )

    # Anonymize Notifications
    Notification.objects.filter(owner=profile).update(
        owner_id=anonymize_user_id(str(profile.id)),
        message="[Notification from deleted user]",
        meta_data={}
    )

    # Delete Stripe customer PII (if exists)
    if profile.stripe_customer_id:
        try:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            stripe.Customer.modify(
                profile.stripe_customer_id,
                name="Deleted User",
                email="deleted@inviteellie.ai",
                phone=None,
                address=None,
                description="GDPR deletion"
            )
            # Detach payment methods
            methods = stripe.PaymentMethod.list(customer=profile.stripe_customer_id)
            for pm in methods.data:
                stripe.PaymentMethod.detach(pm.id)
        except Exception as e:
            print(f"Stripe cleanup failed: {e}")

    # Delete ALL owned data — CASCADE takes care of the rest
    # Since we have ON DELETE CASCADE on:
    # - Workspace.owner_id → Profile.id
    # - Folder.workspace_id → Workspace.id
    # - Meeting.folder_id → Folder.id
    # → Just deleting workspaces is enough!
    deleted_workspaces = Workspace.objects.filter(owner=profile).delete()[0]
    print(f"Deleted {deleted_workspaces} workspaces and all child folders/meetings")

    auth_deleted = delete_supabase_user(str(profile.id))
    if not auth_deleted:
        logger.warning("Supabase Auth user not deleted, continuing anyway")

    original_email = profile.email

    # Mark profile as deleted
    profile.is_active = False
    profile.deleted_at = timezone.now()
    profile.deletion_completed_at = timezone.now()
    profile.email = f"deleted_{profile.id}@email.com"
    profile.first_name = "Deleted"
    profile.last_name = "User"
    profile.save()

    # Log it
    DeletionAuditLog.objects.create(
        profile=profile,
        action="DELETION_COMPLETED",
        metadata={"grace_period_days": grace_period_days}
    )

    # Send final email
    send_mail(
        "Account Permanently Deleted",
        "Your account and all personal data have been permanently deleted as requested.",
        settings.DEFAULT_FROM_EMAIL,
        [original_email],
        fail_silently=True,
    )

    return "Deletion completed successfully"