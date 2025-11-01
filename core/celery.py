import os

from celery import Celery
from decouple import config
import time


environment = config('ENVIRONMENT', default='local')
print(f"Loading settings for environment CELERY: {environment}")

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

app = Celery('invite-ellie')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self, duration=5):
    for i in range(duration):
        self.update_state(state='PROGRESS', meta={'current': i, 'total': duration})
        time.sleep(1)
    print(f'Request: {self.request!r}')
    return f"Task completed successfully! Processed for {duration} seconds"
