from django.conf import settings
import jwt
from accounts.tasks import perform_deletion
from supabase import create_client, Client
import json
from django.utils import timezone
from django.core.mail import send_mail
from workspaces.models import Meeting, Folder, Workspace  
from decouple import config

import json
import boto3
from botocore.client import Config
from django.utils import timezone
from django.conf import settings
from workspaces.models import Meeting, Folder, Workspace


class DataExportService:
    @classmethod
    def _get_s3_client(cls):
        return boto3.client(
            's3',
            endpoint_url=settings.AWS_S3_ENDPOINT_URL,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME,
            config=Config(signature_version='s3v4'),
        )

    @classmethod
    def generate_export(cls, profile):
        try:
            export_data = {
                'export_timestamp': timezone.now().isoformat(),
                'profile_id': str(profile.id),
                'email': profile.email or '',
                'first_name': profile.first_name or '',
                'last_name': profile.last_name or '',
                'workspaces': list(Workspace.objects.filter(owner=profile).values('id', 'name', 'created_at', 'updated_at')),
                'folders': list(Folder.objects.filter(workspace__owner=profile).values('id', 'name', 'workspace__name', 'created_at', 'updated_at')),
                'meetings': list(Meeting.objects.filter(folder__workspace__owner=profile).values('id', 'title', 'transcript', 'summary', 'highlights', 'action_items', 'updated_at')),
            }

            json_content = json.dumps(export_data, indent=2, default=str)
            filename = f"{profile.id}/{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"
            bucket = "exports"  # ← This bucket MUST exist

            s3_client = cls._get_s3_client()
            s3_client.put_object(
                Bucket=bucket,
                Key=filename,
                Body=json_content.encode('utf-8'),
                ContentType='application/json',
            )

            signed_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket, 'Key': filename},
                ExpiresIn=7 * 24 * 60 * 60  # 7 days
            )

            profile.data_exported = True
            profile.data_export_completed_at = timezone.now()
            profile.save()

            return True, signed_url, None

        except Exception as e:
            return False, None, str(e)

    @classmethod
    def _export_workspaces(cls, profile):
        return list(Workspace.objects.filter(owner=profile).values(
            'id', 'name', 'created_at', 'updated_at'
        ))

    @classmethod
    def _export_folders(cls, profile):
        return list(Folder.objects.filter(workspace__owner=profile).values(
            'id', 'name', 'workspace__name', 'created_at', 'updated_at'
        ))

    @classmethod
    def _export_meetings(cls, profile):
        return list(Meeting.objects.filter(folder__workspace__owner=profile).values(
            'id', 'title', 'transcript', 'summary', 'highlights', 'action_items',
            'updated_at'  # Use updated_at since created_at doesn't exist
        ))


class DeletionService:
    @classmethod
    def request_deletion(cls, profile, deletion_type, ip_address):
        if profile.legal_hold:
            return False, "Deletion blocked by legal hold: " + profile.legal_hold_reason_user_facing

        export_success, export_url, export_error = DataExportService.generate_export(profile)
        if not export_success:
            return False, "Data export failed: " + export_error

        profile.deletion_requested_at = timezone.now()
        profile.deletion_requested_by_ip = ip_address
        profile.deletion_type = deletion_type
        profile.save()

        # Send confirmation email
        cls._send_deletion_confirmation(profile, export_url)

        # Schedule actual deletion
        if deletion_type == 'IMMEDIATE':
            perform_deletion.delay(profile.id)
        else:
            perform_deletion.delay(profile.id, grace_period_days=7)

        return True, export_url

    @classmethod
    def _send_deletion_confirmation(cls, profile, export_url):
        send_mail(
            'Deletion Request Confirmation',
            f'Your deletion request has been received. Download your data here: {export_url}',
            settings.DEFAULT_FROM_EMAIL,
            [profile.email],
        )
