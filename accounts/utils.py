from django.conf import settings
import jwt
from core.supabase import supabase
from supabase import create_client, Client
from django.conf import settings
import logging
import requests

logger = logging.getLogger(__name__)

def get_supabase_user_id(request):
    """Extract Supabase user ID (sub) from JWT"""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        logger.warning("Missing Bearer token")
        return None
    token = auth_header.split(' ')[1]
    try:
        # Decode without verification (service_role will validate)
        payload = jwt.decode(token, options={"verify_signature": False})
        sub = payload.get('sub')
        if not sub:
            logger.warning("JWT missing 'sub'")
        return sub
    except Exception as e:
        logger.error(f"JWT decode failed: {e}")
        return None


def update_supabase_password(supabase_user_id: str, new_password: str):
    """Update password using service_role key in headers"""
    url = f"{settings.SUPABASE_URL}/auth/v1/admin/users/{supabase_user_id}"
    headers = {
        "apikey": settings.SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json"
    }
    data = {"password": new_password}

    try:
        response = requests.put(url, json=data, headers=headers)
        if response.status_code == 200:
            logger.info(f"Password updated in Supabase for user ID: {supabase_user_id}")
            return True
        else:
            logger.error(f"Supabase update failed: {response.status_code} {response.text}")
            return False
    except Exception as e:
        logger.error(f"Supabase request failed: {e}")
        return False


def email_exists_in_supabase(email: str) -> bool:
    """
    Check if email exists in Supabase auth.users using Admin API
    """
    url = f"{settings.SUPABASE_URL}/auth/v1/admin/users"
    headers = {
        "apikey": settings.SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "filter": {"email": {"eq": email.lower()}}
    }

    try:
        response = requests.get(url, headers=headers, params=payload)
        if response.status_code == 200:
            data = response.json()
            return len(data.get("users", [])) > 0
        else:
            logger.warning(f"Supabase admin check failed: {response.status_code} {response.text}")
            return False  # Fail open (don't block signup)
    except Exception as e:
        logger.error(f"Error checking email existence: {e}")
        return False


def check_user_exists(email: str):
    supabase_admin: Client = create_client(
        settings.SUPABASE_URL,
        settings.SUPABASE_SERVICE_ROLE_KEY  # Must be SERVICE ROLE, not anon/public
    )

    try:
        response = (
            supabase_admin.auth.admin.list_users()
        )

        email_lower = email.lower()
        for user in response:
            if user.email and user.email.lower() == email_lower:
                logger.debug("Found existing user: %s (id=%s)", user.email, user.id)
                return True

        logger.debug("No user found with email: %s", email_lower)
        return False

    except Exception as e:
        logger.error("Error checking email in Supabase: %s", e)
        return False  # Fail-open