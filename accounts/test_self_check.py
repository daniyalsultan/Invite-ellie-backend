"""Backend checks, and the nightly job that shouts about both services."""

from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone

from accounts import self_check


class BeatSilenceTests(TestCase):
    def task(self, name, last_run_at=None, hours_since_change=0, enabled=True):
        from django_celery_beat.models import CrontabSchedule, PeriodicTask

        schedule, _ = CrontabSchedule.objects.get_or_create(minute='0', hour='3')
        task = PeriodicTask.objects.create(
            name=name, task='accounts.tasks.whatever', crontab=schedule,
            enabled=enabled, last_run_at=last_run_at)
        if hours_since_change:
            PeriodicTask.objects.filter(pk=task.pk).update(
                date_changed=timezone.now() - timezone.timedelta(hours=hours_since_change))
        return task

    def test_it_fires_on_a_job_that_has_stopped(self):
        self.task('stalled', last_run_at=timezone.now() - timezone.timedelta(
            hours=self_check.BEAT_SILENT_HOURS + 1))
        result = self_check.beat_tasks_silent()
        self.assertIsNotNone(result)
        self.assertIn('stalled', result['detail'])

    def test_a_job_that_ran_this_morning_is_quiet(self):
        self.task('healthy', last_run_at=timezone.now() - timezone.timedelta(hours=2))
        self.assertIsNone(self_check.beat_tasks_silent())

    def test_a_job_just_added_is_given_time_to_run(self):
        """A reconciler added tonight has not failed by morning."""
        self.task('brand-new', last_run_at=None, hours_since_change=0)
        self.assertIsNone(self_check.beat_tasks_silent())

    def test_a_job_that_has_never_run_in_days_is_reported(self):
        """One existed unscheduled for eleven days."""
        self.task('never-ran', last_run_at=None,
                  hours_since_change=self_check.BEAT_SILENT_HOURS + 1)
        self.assertIsNotNone(self_check.beat_tasks_silent())

    def test_a_disabled_job_is_not_expected_to_run(self):
        self.task('switched-off', last_run_at=None,
                  hours_since_change=self_check.BEAT_SILENT_HOURS + 1, enabled=False)
        self.assertIsNone(self_check.beat_tasks_silent())

    def test_celerys_own_cleanup_is_not_our_business(self):
        self.task('celery.backend_cleanup', last_run_at=None,
                  hours_since_change=self_check.BEAT_SILENT_HOURS + 1)
        self.assertIsNone(self_check.beat_tasks_silent())


class ScheduleRegistrationTests(TestCase):
    @override_settings(CELERY_BEAT_SCHEDULE={
        'ghost': {'task': 'accounts.tasks.renamed_away'}})
    def test_it_fires_when_a_beat_entry_names_a_missing_task(self):
        result = self_check.scheduled_tasks_registered()
        self.assertIsNotNone(result)
        self.assertIn('renamed_away', result['detail'])

    def test_the_real_schedule_is_clean(self):
        self.assertIsNone(self_check.scheduled_tasks_registered(),
                          'a beat entry names a task that is not registered')


class ConfigTests(TestCase):
    @override_settings(DEBUG=True)
    def test_debug_on_is_reported(self):
        self.assertIsNotNone(self_check.debug_enabled())

    @override_settings(RECALL_SERVER_URL='', INTERNAL_API_KEY='')
    def test_an_unconfigured_link_is_reported(self):
        self.assertIsNotNone(self_check.internal_api_reachable())

    @override_settings(RECALL_SERVER_URL='https://example.test', INTERNAL_API_KEY='k')
    def test_a_configured_link_is_quiet(self):
        self.assertIsNone(self_check.internal_api_reachable())


class NightlyJobTests(TestCase):
    """The job has to make noise, or it is another thing nobody notices."""

    def run_task(self, local, remote=None, remote_error=None):
        from accounts.tasks import run_self_checks

        response = mock.Mock()
        response.json.return_value = {'findings': remote or []}
        response.raise_for_status.return_value = None
        post = mock.Mock(return_value=response)
        if remote_error:
            post.side_effect = RuntimeError(remote_error)
        with mock.patch.object(self_check, 'run', return_value=local), \
             mock.patch('requests.post', post), \
             self.settings(RECALL_SERVER_URL='https://example.test', INTERNAL_API_KEY='k'):
            return run_self_checks()

    def test_a_clean_run_returns_quietly(self):
        result = self.run_task(local=[])
        self.assertTrue(result['ok'])

    def test_it_raises_when_something_is_wrong(self):
        finding = {'check': 'debug_enabled', 'detail': 'DEBUG is True',
                   'count': 1, 'from': 'DEBUG left on'}
        with self.assertRaises(RuntimeError) as caught:
            self.run_task(local=[finding])
        self.assertIn('debug_enabled', str(caught.exception))

    def test_a_finding_from_the_other_service_counts(self):
        remote = [{'check': 'stranded_bots', 'detail': '2 bots', 'count': 2,
                   'from': 'a webhook that never landed'}]
        with self.assertRaises(RuntimeError) as caught:
            self.run_task(local=[], remote=remote)
        self.assertIn('stranded_bots', str(caught.exception))

    def test_not_being_able_to_ask_is_itself_a_finding(self):
        """A broken link must not look like a clean bill of health."""
        with self.assertRaises(RuntimeError) as caught:
            self.run_task(local=[], remote_error='connection refused')
        self.assertIn('recall_server_unreachable', str(caught.exception))

    def test_findings_are_logged_at_error_so_something_can_see_them(self):
        finding = {'check': 'debug_enabled', 'detail': 'DEBUG is True',
                   'count': 1, 'from': 'DEBUG left on'}
        with self.assertLogs('accounts.tasks', level='ERROR') as logged:
            with self.assertRaises(RuntimeError):
                self.run_task(local=[finding])
        self.assertTrue(any('debug_enabled' in line for line in logged.output))
