# core/middleware.py
import uuid
from django_guid import set_guid, get_guid

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