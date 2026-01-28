# core/middleware.py
import uuid
import logging
from django_guid import set_guid, get_guid
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class CorrelationIDMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        guid = request.META.get('HTTP_X_CORRELATION_ID')
        if not guid:
            guid = str(uuid.uuid4())

        set_guid(guid)
        response = self.get_response(request)
        response['X-Correlation-ID'] = guid
        if hasattr(response, 'data') and isinstance(response.data, dict):
            response.data['correlation_id'] = guid

        return response




class ThrottleMonitorMiddleware(MiddlewareMixin):
    """
    Middleware to monitor and log throttled requests (429 status code).
    """

    def process_response(self, request, response):
        # Check if the response is a throttling response (429 Too Many Requests)
        if response.status_code == 429:
            # Extract relevant information
            user_info = (
                f"User: {request.profile.email}"
                if request.profile.is_authenticated
                else "User: Anonymous"
            )

            ip_address = request.META.get('REMOTE_ADDR', 'Unknown IP')
            forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

            if forwarded_for:
                ip_address = f"{ip_address} (X-Forwarded-For: {forwarded_for})"

            # Get additional throttle info if available
            throttle_info = ""
            if hasattr(response, 'data'):
                if isinstance(response.data, dict):
                    throttle_info = response.data.get('detail', '')

            # Log the throttling event
            logger.warning(
                f"THROTTLE ALERT - "
                f"Path: {request.path} - "
                f"{user_info} - "
                f"IP: {ip_address} - "
                f"Method: {request.method} - "
                f"Throttle Info: {throttle_info}"
            )

            # You can also add custom headers or additional processing here
            response['X-Throttle-Monitored'] = 'True'
            response['X-Throttle-User'] = user_info

        return response
