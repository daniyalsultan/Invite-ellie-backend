import logging

class UserIDFilter(logging.Filter):
    def filter(self, record):
        # Get request from thread-local storage (set by django-guid)
        request = getattr(logging.getLogger(), 'request', None)
        profile = getattr(request, 'profile', None) if request else None

        # Safe: Don't import Django models
        record.user_id = str(profile.id) if profile and hasattr(profile, 'id') else 'anonymous'
        return True