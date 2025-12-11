from django.conf import settings
import jwt
from supabase import create_client, Client
from django.db import connection
import json
from django.utils import timezone
from django.core.mail import send_mail
from accounts.models import DeletionAuditLog, Profile
from workspaces.models import Meeting, Folder, Workspace  
import stripe
import logging
import requests
import base64
import secrets
import hashlib


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
        "filter": email.lower()
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
        return False



def _pkce_pair() -> tuple[str, str]:
    """Return (verifier, challenge) according to RFC 7636."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b'=').decode()
    return verifier, challenge


def get_user_db_size_bytes(user_id: str) -> dict:
    """
    Exact PostgreSQL storage used by ONE user.

    Returns:
        {
            "total_bytes": int,
            "breakdown": {
                "workspace_rows": int,
                "folder_rows": int,
                "meeting_rows": int,
                "meeting_toast": int,
                "indexes": int,
            }
        }
    """
    with connection.cursor() as cur:

        # Row sizes (main table rows)
        cur.execute(
            "SELECT COALESCE(SUM(pg_column_size(w.*)), 0) FROM workspaces_workspace w WHERE w.owner_id = %s;",
            [user_id],
        )
        workspace_bytes = int(cur.fetchone()[0] or 0)

        cur.execute(
            """
            SELECT COALESCE(SUM(pg_column_size(f.*)), 0)
            FROM workspaces_folder f
            JOIN workspaces_workspace w ON f.workspace_id = w.id
            WHERE w.owner_id = %s;
            """,
            [user_id],
        )
        folder_bytes = int(cur.fetchone()[0] or 0)

        cur.execute(
            """
            SELECT COALESCE(SUM(pg_column_size(m.*)), 0)
            FROM workspaces_meeting m
            JOIN workspaces_folder f ON m.folder_id = f.id
            JOIN workspaces_workspace w ON f.workspace_id = w.id
            WHERE w.owner_id = %s;
            """,
            [user_id],
        )
        meeting_row_bytes = int(cur.fetchone()[0] or 0)

        # TOAST size (transcript, summary, highlights, action_items)
        cur.execute(
            """
            WITH user_meetings AS (
                SELECT m.id::text
                FROM workspaces_meeting m
                JOIN workspaces_folder f ON m.folder_id = f.id
                JOIN workspaces_workspace w ON f.workspace_id = w.id
                WHERE w.owner_id = %s
            )
            SELECT COALESCE(SUM(pg_total_relation_size(c.oid)), 0)
            FROM pg_class c
            JOIN user_meetings um ON c.relname = 'workspaces_meeting_' || um.id
            WHERE c.relkind = 't';
            """,
            [user_id],
        )
        meeting_toast_bytes = int(cur.fetchone()[0] or 0)

        # Index size – pro-rated by number of workspaces the user owns
        cur.execute(
            """
            SELECT COALESCE(SUM(pg_indexes_size(c.oid)), 0)
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname IN ('workspaces_workspace', 'workspaces_folder', 'workspaces_meeting')
              AND n.nspname = 'public';
            """
        )
        total_index_bytes_result = cur.fetchone()[0]

        # Handle the Decimal conversion properly
        if total_index_bytes_result is None:
            total_index_bytes = 0
        else:
            # Convert Decimal to int immediately
            total_index_bytes = int(total_index_bytes_result)

        cur.execute("SELECT COUNT(*) FROM workspaces_workspace WHERE owner_id = %s;", [user_id])
        user_workspaces_result = cur.fetchone()[0]
        user_workspaces = int(user_workspaces_result or 0)

        cur.execute("SELECT COUNT(*) FROM workspaces_workspace;")
        total_workspaces_result = cur.fetchone()[0]
        total_workspaces = int(total_workspaces_result or 1)

        # Calculate user's share of index bytes
        share = user_workspaces / total_workspaces
        user_index_bytes = int(total_index_bytes * share)

        # Grand total
        total_bytes = (
            workspace_bytes
            + folder_bytes
            + meeting_row_bytes
            + meeting_toast_bytes
            + user_index_bytes
        )

        return {
            "total_bytes": total_bytes,
            "breakdown": {
                "workspace_rows": workspace_bytes,
                "folder_rows": folder_bytes,
                "meeting_rows": meeting_row_bytes,
                "meeting_toast": meeting_toast_bytes,
                "indexes": user_index_bytes,
            },
        }
    

def delete_stripe_pii(stripe_customer_id):
    stripe.api_key = settings.STRIPE_SECRET_KEY
    stripe.Customer.modify(
        stripe_customer_id,
        name='Deleted User',
        email='deleted@invite-ellie.com',
        phone=None,
        address=None,
        description='Account deleted per GDPR'
    )
    # Delete payment methods
    methods = stripe.PaymentMethod.list(customer=stripe_customer_id)
    for pm in methods.data:
        stripe.PaymentMethod.detach(pm.id)

def pseudonymize_audit_logs(profile_id):
    pseudo_id = hashlib.sha256(f'{profile_id}{settings.AUDIT_LOG_SALT}'.encode()).hexdigest()
    DeletionAuditLog.objects.filter(profile_id=profile_id).update(
        profile_id=pseudo_id,
        pseudonymized=True,
        pseudonymized_at=timezone.now()
    )


def delete_supabase_user(user_id: str) -> bool:
    """
    Permanently delete a user from Supabase Auth using the service_role key.
    Returns True on success, False on failure.
    """
    supabase_admin: Client = create_client(
        settings.SUPABASE_URL,
        settings.SUPABASE_SERVICE_ROLE_KEY  # Must be service_role — bypasses RLS
    )

    try:
        response = supabase_admin.auth.admin.delete_user(user_id)
        logger.info("Successfully deleted Supabase Auth user: %s", user_id)
        return True
        
    except Exception as e:
        logger.error("Failed to delete Supabase Auth user %s: %s", user_id, str(e))
        return False
    

def anonymize_user_id(user_id: str) -> str:
    """
    Convert a UUID into a fixed, irreversible pseudonym.
    Same input → always same output (deterministic).
    """
    salt = getattr(settings, settings.ANONYMIZATION_SALT, 'default-salt-change-me')
    return hashlib.sha256(f"{user_id}{salt}".encode()).hexdigest()[:32]


def anonymize_email(email: str) -> str:
    """Convert email → anonymized version"""
    if not email:
        return "deleted@email.com"
    return f"deleted_{hashlib.md5(email.lower().encode()).hexdigest()[:8]}@email.com"