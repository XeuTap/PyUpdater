import logging
import os

import boto3
from boto3 import Session

from pyupdater.utils.exceptions import AuthorizationError

log = logging.getLogger(__name__)


def get_session() -> boto3.Session:
    access_key = os.environ.get('PYU_AWS_ID')
    if access_key is None:
        raise AuthorizationError('Missing PYU_AWS_ID')
    secret_key = os.environ.get('PYU_AWS_SECRET')
    if secret_key is None:
        raise AuthorizationError('Missing PYU_AWS_SECRET')
    session_token = os.environ.get('PYU_AWS_SESSION_TOKEN')
    bucket_region = os.environ.get('PYU_AWS_BUCKET_REGION', None)
    if bucket_region is None:
        raise AuthorizationError('Bucket region is not set')

    log.debug('Initializing session. Bucket region is {}'.format(bucket_region))
    session = Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=bucket_region
    )
    return session
