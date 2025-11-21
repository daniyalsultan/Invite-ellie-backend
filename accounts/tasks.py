from cProfile import Profile
from .models import ProfileStorage
from .utils import get_user_db_size_bytes
from supabase import create_client
import logging
from decouple import config
from datetime import timezone
from celery import shared_task, signals
from django.core.mail import send_mail
from django.conf import settings

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