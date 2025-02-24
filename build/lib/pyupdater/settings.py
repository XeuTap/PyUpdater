# ------------------------------------------------------------------------------
# Copyright (c) 2015-2019 Digital Sapphire
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the
# following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
# ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
# TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
# ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.
# ------------------------------------------------------------------------------
from __future__ import unicode_literals

import datetime
import os
import struct
import sys
from enum import StrEnum

from dsdev_utils import system

APP_NAME = "PyUpdater"
APP_AUTHOR = "Digital Sapphire"

# Used to hold PyUpdater config info for repo
CONFIG_DATA_FOLDER = ".pyupdater"

# User config file
CONFIG_FILE_USER = "config.pyu"

CONFIG_DB_KEY_APP_CONFIG = "app_config"
CONFIG_DB_KEY_KEYPACK = "keypack"
CONFIG_DB_KEY_PY_REPO_CONFIG = "py_repo_config"

DEFAULT_CLIENT_CONFIG = ["client_config.py"]

GENERIC_APP_NAME = "PyUpdater App"
GENERIC_COMPANY_NAME = "PyUpdater"

# Log filename
LOG_FILENAME_DEBUG = "pyu-debug.log"

# KeyFile
KEYPACK_FILENAME = "keypack.pyu"

# Main user visible data folder
USER_DATA_FOLDER = "pyu-data"

# Key in version file where value are update meta data
UPDATES_KEY = "updates"

# Folder on client system where updates are stored
UPDATE_FOLDER = "update"
UPDATER_FOLDER = "updater"

# Name of version file in online repo
VERSION_FILE_FILENAME = "versions.gz"
VERSION_FILE_FILENAME_COMPAT = "versions.gz"
KEY_FILE_FILENAME = "keys.gz"


class StorageLocation(StrEnum):
    LOCAL = "local"
    AWS = "aws"


VERSION_META_FILE = "version_meta.json"
_storage_location = os.environ.get("PYU_STORAGE_LOCATION", None)
if _storage_location:
    STORAGE_LOCATION = StorageLocation(_storage_location)
else:
    STORAGE_LOCATION = None
STORAGE_BUCKET_NAME = os.environ.get("PYU_STORAGE_BUCKET_NAME", None)
STORAGE_BUCKET_REGION = os.environ.get("PYU_STORAGE_BUCKET_REGION", None)
STORAGE_BUCKET_KEY = os.environ.get("PYU_STORAGE_BUCKET_KEY", "")
STORAGE_BUCKET_SIGNATURE_VERSION = "s3v4"
STORAGE_LOCK_KEY = "version_meta_lock"
if STORAGE_LOCATION is not None and STORAGE_LOCATION != StorageLocation.LOCAL:
    if STORAGE_BUCKET_NAME is None:
        raise Exception("PYU_STORAGE_BUCKET_NAME must be set in environment if PYU_STORAGE_LOCATION is not local")
    if STORAGE_BUCKET_REGION is None:
        raise Exception("PYU_STORAGE_BUCKET_REGION must be set in environment if PYU_STORAGE_LOCATION is not local")

OFFLINE_PUBLIC_KEY = "PYU_OFFLINE_PUBLIC"
APP_PRIVATE_KEY = "PYU_APP_PRIVATE"
UPLOAD_APP_PUBLIC_KEY = "PYU_UPLOAD_APP_PUBLIC"
UPLOAD_SIGNATURE_KEY = "PYU_UPLOAD_SIGNATURE"

DEFAULT_S3STORAGE_EXPIRY_PERIOD = 2
DEFAULT_S3STORAGE_LEASE_DURATION = 30
DEFAULT_S3STORAGE_SAFE_PERIOD = 20
DEFAULT_S3STORAGE_HEARTBEAT_PERIOD = 10
DEFAULT_S3STORAGE_RETRY_PERIOD = 1
DEFAULT_S3STORAGE_RETRY_TIMEOUT = 40

S3STORAGE_EXPIRY_PERIOD = datetime.timedelta(days=float(os.environ.get("PYU_S3STORAGE_EXPIRY_PERIOD", DEFAULT_S3STORAGE_EXPIRY_PERIOD)))
S3STORAGE_LEASE_DURATION = datetime.timedelta(minutes=float(os.environ.get("PYU_S3STORAGE_LEASE_DURATION", DEFAULT_S3STORAGE_LEASE_DURATION)))
S3STORAGE_SAFE_PERIOD = datetime.timedelta(minutes=float(os.environ.get("PYU_S3STORAGE_SAFE_PERIOD", DEFAULT_S3STORAGE_SAFE_PERIOD)))
S3STORAGE_HEARTBEAT_PERIOD = datetime.timedelta(minutes=float(os.environ.get("PYU_S3STORAGE_HEARTBEAT_PERIOD", DEFAULT_S3STORAGE_HEARTBEAT_PERIOD)))
S3STORAGE_RETRY_PERIOD = datetime.timedelta(minutes=float(os.environ.get("PYU_S3STORAGE_RETRY_PERIOD", DEFAULT_S3STORAGE_RETRY_PERIOD)))
S3STORAGE_RETRY_TIMEOUT = datetime.timedelta(minutes=float(os.environ.get("PYU_S3STORAGE_RETRY_TIMEOUT", DEFAULT_S3STORAGE_RETRY_TIMEOUT)))
