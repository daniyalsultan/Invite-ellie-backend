from cProfile import Profile
from .models import ProfileStorage
from .utils import get_user_db_size_bytes
from supabase import create_client
import logging
from decouple import config
from datetime import timezone
from celery import shared_task


logger = logging.getLogger(__name__)
supabase = create_client(config("SUPABASE_URL"), config("SUPABASE_ANON_KEY"))

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

        user = Profile.objects.filter(id=user_id).first()

        if user:
            user.generate

        return {
            'user_id': user_id,
            'total_mb': total_mb,
            'breakdown': db_stats['breakdown'],
            'supabase_mb': round(supabase_bytes / (1024*1024), 2),
        }

    except Exception as exc:
        logger.exception("Storage calc failed")
        self.retry(exc=exc)