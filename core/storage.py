# storages.py (in your app, e.g. accounts/storages.py)
from storages.backends.s3 import S3Storage
from django.conf import settings
import boto3
from botocore.client import Config

class SupabaseSignedStorage(S3Storage):
    """S3Storage that can generate signed URLs with custom expiry."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # boto3 client with signature v4 (required by Supabase)
        self.s3_client = boto3.client(
            's3',
            endpoint_url=settings.AWS_S3_ENDPOINT_URL,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME,
            config=Config(signature_version='s3v4'),
        )

    def signed_url(self, name, expire=600):
        """
        Return a signed URL valid for `expire` seconds.
        """
        return self.s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': settings.AWS_STORAGE_BUCKET_NAME,
                'Key': name,
            },
            ExpiresIn=expire,
            HttpMethod='GET',
        )