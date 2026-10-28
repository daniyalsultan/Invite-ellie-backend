"""Checks on this service, taken from things that went wrong here.

The companion to recall-server's `app/logic/self_check.py`. Same reasoning:
every incident worth preventing was a wrong state rather than a crash, so
error tracking would not have seen any of them. Each check names the
incident it came from, and a check nobody can explain the failure of is not
worth running.
"""

import logging

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

# A daily job that has not run in two days is not running. The retention
# sweep and the monthly orphan check were both registered but dead, and the
# bot reconciler existed unscheduled for eleven days.
BEAT_SILENT_HOURS = 48


def finding(name, detail, count, where):
    return {'check': name, 'detail': detail, 'count': count, 'from': where}


def beat_tasks_silent():
    """A scheduled job that has stopped running.

    From: a reconciler written on 17 October and never scheduled; a monthly
    job registered in settings that never appeared in the scheduler; and a
    stale row left behind pointing at a task that no longer existed.
    """
    from django_celery_beat.models import PeriodicTask

    cutoff = timezone.now() - timezone.timedelta(hours=BEAT_SILENT_HOURS)
    silent = []
    for task in PeriodicTask.objects.filter(enabled=True).exclude(
            name='celery.backend_cleanup'):
        # A task that has never run and was only just created is not silent;
        # one that has never run and is older than the window is.
        last = task.last_run_at
        if last is None:
            if task.date_changed and task.date_changed < cutoff:
                silent.append(f'{task.name} (never run)')
            continue
        if last < cutoff:
            silent.append(f'{task.name} (last {last:%Y-%m-%d %H:%M})')
    if not silent:
        return None
    return finding('beat_tasks_silent',
                   f'{len(silent)} scheduled job(s) silent for over '
                   f'{BEAT_SILENT_HOURS}h: {"; ".join(silent[:5])}',
                   len(silent), 'jobs registered but never running')


def scheduled_tasks_registered():
    """A beat entry naming a task that does not exist.

    From: a settings entry pointing at a task that had been renamed, which
    fails only when it fires, in a worker log nobody reads.
    """
    from core.celery import app as celery_app

    # The registry is only populated once the task modules are imported. In a
    # worker they are, but a check that depends on being called at the right
    # moment reports healthy jobs as missing -- which is worse than no check
    # at all, because it teaches people to ignore it.
    try:
        celery_app.loader.import_default_modules()
    except Exception as error:
        return finding('scheduled_tasks_registered',
                       f'could not load the task modules to check them: {error}',
                       1, 'a check that cannot be trusted')

    missing = []
    for name, entry in (settings.CELERY_BEAT_SCHEDULE or {}).items():
        task = entry.get('task')
        if task and task not in celery_app.tasks:
            missing.append(f'{name} -> {task}')
    if not missing:
        return None
    return finding('scheduled_tasks_registered',
                   f'{len(missing)} beat entr(ies) name a task that is not '
                   f'registered: {"; ".join(missing)}',
                   len(missing), 'a beat entry pointing at a renamed task')


def debug_enabled():
    """Django debug pages in production.

    From: this service served full debug pages, settings included.
    """
    if not settings.DEBUG:
        return None
    return finding('debug_enabled', 'DEBUG is True, which serves tracebacks and settings',
                   1, 'DEBUG left on in production')


def internal_api_reachable():
    """Whether this service can still talk to recall-server.

    From: the backend pointed at a dead hostname for months, and the only
    symptom was work silently not happening.
    """
    url = getattr(settings, 'RECALL_SERVER_URL', '') or ''
    key = getattr(settings, 'INTERNAL_API_KEY', '') or ''
    if not url or not key:
        return finding('internal_api_reachable',
                       'RECALL_SERVER_URL or INTERNAL_API_KEY is not configured, '
                       'so cross-service jobs cannot run',
                       1, 'a service pointed at a dead hostname')
    return None


CHECKS = (
    beat_tasks_silent,
    scheduled_tasks_registered,
    debug_enabled,
    internal_api_reachable,
)


def run():
    """Every check. Empty list when all is well.

    A check that raises is reported rather than allowed to stop the rest.
    """
    findings = []
    for check in CHECKS:
        try:
            result = check()
        except Exception as error:
            findings.append(finding(check.__name__, f'the check itself failed: {error}',
                                    1, 'a broken check'))
            continue
        if result:
            findings.append(result)
    return findings
