# core/supabase.py
from django.conf import settings
from supabase import create_client, Client
import os

class SupabaseClient:
    _client: Client = None
    _service_client: Client = None

    @classmethod
    def get_client(cls) -> Client:
        if cls._client is None:
            cls._client = create_client(
                settings.SUPABASE_URL,
                settings.SUPABASE_ANON_KEY
            )
        return cls._client

    @classmethod
    def get_service_client(cls) -> Client:
        if cls._service_client is None:
            cls._service_client = create_client(
                settings.SUPABASE_URL,
                settings.SUPABASE_SERVICE_ROLE_KEY
            )
        return cls._service_client

supabase = SupabaseClient.get_client()
supabase_service = SupabaseClient.get_service_client()