"""Bring Profile subscription state back in line with Stripe.

Stripe is the source of truth for what someone is paying for; the Profile
fields are a local cache of it, kept up to date by the webhook. That cache has
drifted, for two reasons worth stating so this command's job is clear:

* The webhook endpoint pointed at a domain that no longer resolved, so months
  of `checkout.session.completed`, `invoice.paid` and
  `customer.subscription.deleted` events were never delivered and are now past
  Stripe's retry window. They cannot be replayed — only reconciled.
* `customer.subscription.updated` is handled in code but was never subscribed
  on the endpoint, so plan changes, cancel-at-period-end, and past_due
  transitions have never reached the database at all.

What survived did so by accident: `SubscriptionDetailView` re-reads Stripe when
a profile has a customer id but no subscription id, so anyone who happened to
open the subscription page healed themselves. Anyone who didn't, didn't.

Run with no arguments to see what would change. Nothing is written without
--apply.
"""

from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone as django_timezone
from datetime import datetime, timezone as dt_timezone

import stripe

from accounts.models import Profile


# Statuses Stripe can legitimately report, plus the local-only 'free'. Anything
# else in the column is junk that got there by some other route.
KNOWN_STATUSES = {
    'free', 'active', 'trialing', 'canceled', 'past_due', 'unpaid',
    'incomplete', 'incomplete_expired', 'paused', '',
}

# A subscription in one of these states entitles someone to their plan.
ENTITLING = {'active', 'trialing'}


class Command(BaseCommand):
    help = 'Reconcile Profile subscription fields against Stripe. Read-only unless --apply.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--apply', action='store_true',
            help='Actually write the changes. Without this the command only reports.',
        )
        parser.add_argument(
            '--profile', dest='profile_id', default=None,
            help='Reconcile a single profile by id instead of everyone.',
        )

    def handle(self, *args, **options):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        apply_changes = options['apply']

        price_to_plan = {
            getattr(settings, 'STRIPE_PRICE_CLARITY', ''): 'clarity',
            getattr(settings, 'STRIPE_PRICE_INSIGHT', ''): 'insight',
            getattr(settings, 'STRIPE_PRICE_ALIGNMENT', ''): 'alignment',
        }

        profiles = Profile.objects.all()
        if options['profile_id']:
            profiles = profiles.filter(id=options['profile_id'])
        # Nothing can be reconciled without a Stripe customer to look up.
        profiles = profiles.exclude(stripe_customer_id__isnull=True).exclude(stripe_customer_id='')

        self.stdout.write(
            f'Reconciling {profiles.count()} profile(s) with a Stripe customer id '
            f'({"APPLYING" if apply_changes else "dry run — nothing will be written"})'
        )

        changed = unchanged = failed = 0

        for profile in profiles:
            try:
                subscription = self._live_subscription(profile, ENTITLING)
            except Exception as error:
                failed += 1
                self.stderr.write(f'  {profile.email}: could not read Stripe ({error})')
                continue

            updates = self._desired_state(profile, subscription, price_to_plan)
            if not updates:
                unchanged += 1
                continue

            changed += 1
            summary = ', '.join(
                f'{field}: {getattr(profile, field)!r} -> {value!r}'
                for field, value in updates.items()
            )
            self.stdout.write(f'  {profile.email}: {summary}')

            if apply_changes:
                for field, value in updates.items():
                    setattr(profile, field, value)
                profile.save(update_fields=list(updates))

        self.stdout.write('')
        self.stdout.write(
            f'{changed} profile(s) {"updated" if apply_changes else "would change"}, '
            f'{unchanged} already correct, {failed} could not be read.'
        )
        if changed and not apply_changes:
            self.stdout.write('Re-run with --apply to write these changes.')

    def _live_subscription(self, profile, entitling):
        """The subscription Stripe currently has for this customer, or None.

        Prefers the one already recorded on the profile so an existing link is
        never silently swapped for a different subscription; falls back to
        whatever entitling subscription the customer has, which is how a
        checkout whose webhook never arrived gets picked up.
        """
        if profile.stripe_subscription_id:
            try:
                return stripe.Subscription.retrieve(profile.stripe_subscription_id)
            except stripe.error.InvalidRequestError:
                # The id on the profile is a ghost — Stripe has no such
                # subscription. Fall through and look for a real one.
                pass

        for status in ('active', 'trialing'):
            found = stripe.Subscription.list(
                customer=profile.stripe_customer_id, status=status, limit=1,
            )
            if found.data:
                return found.data[0]
        return None

    def _desired_state(self, profile, subscription, price_to_plan):
        """Fields that differ from what Stripe says, as {field: new_value}."""
        updates = {}

        def want(field, value):
            if getattr(profile, field) != value:
                updates[field] = value

        if subscription is None or subscription.status not in ENTITLING:
            # No entitling subscription: the account is on the free tier. Keep a
            # real cancelled status rather than inventing one, but never leave a
            # subscription id pointing at something that does not entitle.
            want('subscription_plan', 'free')
            want('stripe_subscription_id', None)
            status = subscription.status if subscription is not None else 'free'
            want('subscription_status', status if status in KNOWN_STATUSES else 'free')
            want('subscription_end_date', None)
            return updates

        want('stripe_subscription_id', subscription.id)
        want('subscription_status', subscription.status)

        items = subscription['items']['data']
        price_id = items[0]['price']['id'] if items else None
        plan = price_to_plan.get(price_id)
        if plan:
            want('subscription_plan', plan)
        else:
            self.stderr.write(
                f'  {profile.email}: price {price_id} matches no configured plan, leaving '
                f'plan as {profile.subscription_plan!r}'
            )

        # current_period_end sits on the subscription in older API versions and
        # on the item in newer ones; take whichever this account returns.
        period_end = subscription.get('current_period_end')
        if period_end is None and items:
            period_end = items[0].get('current_period_end')
        if period_end:
            want('subscription_end_date', datetime.fromtimestamp(period_end, tz=dt_timezone.utc))

        want('subscription_auto_renew', not subscription.get('cancel_at_period_end', False))
        return updates
