# ------------------------------------------------------------------------------
# Copyright (c) 2015-2020 Digital Sapphire
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
from __future__ import print_function, unicode_literals

import atexit
import datetime
import io
import json
import logging
import os
import time
import warnings
from abc import abstractmethod
from typing import Self, LiteralString, Any

import boto3
import botocore
from botocore.config import Config
from python_dynamodb_lock.python_dynamodb_lock import DynamoDBLockClient, DynamoDBLock

from pyupdater import settings
from pyupdater.settings import StorageLocation
from pyupdater.utils import JSONStore
from pyupdater.utils.meta import Singleton

log = logging.getLogger(__name__)


class BaseStorage:
    def __init__(self, path: str | LiteralString | bytes):
        self.path = path

    @abstractmethod
    def load(self) -> dict | None:
        pass

    @abstractmethod
    def save(self, data: dict) -> None:
        pass


class LocalStorage(BaseStorage):
    def load(self) -> dict | None:
        if not os.path.isfile(self.path):
            return None
        with open(self.path, "r") as file:
            return json.load(file)

    def save(self, data: dict) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as file:
            json.dump(data, file)


class S3Storage(BaseStorage):
    bucket: Any
    lock: DynamoDBLock | None

    def __init__(self, path: str | LiteralString | bytes):
        super().__init__(path)
        # acquire lock
        self.lock = None
        aws_config = Config(signature_version=settings.STORAGE_BUCKET_SIGNATURE_VERSION)
        dynamodb_resource = boto3.resource('dynamodb', region_name=settings.STORAGE_BUCKET_REGION)
        lock_client = DynamoDBLockClient(dynamodb_resource,
                                         expiry_period=settings.S3STORAGE_EXPIRY_PERIOD,
                                         lease_duration=settings.S3STORAGE_LEASE_DURATION,
                                         safe_period=settings.S3STORAGE_SAFE_PERIOD,
                                         heartbeat_period=settings.S3STORAGE_HEARTBEAT_PERIOD,
                                         )
        self.lock = lock_client.acquire_lock(settings.STORAGE_LOCK_KEY,
                                             retry_period=settings.S3STORAGE_RETRY_PERIOD,
                                             retry_timeout=settings.S3STORAGE_RETRY_TIMEOUT,
                                             )
        s3 = boto3.resource("s3", config=aws_config, region_name=settings.STORAGE_BUCKET_REGION)
        self.bucket = s3.Bucket(settings.STORAGE_BUCKET_NAME)
        atexit.register(self.cleanup)

    def cleanup(self) -> None:
        print("Releasing a lock ")
        if self.lock:
            self.lock.release()

    def load(self) -> dict | None:
        try:
            data = io.BytesIO()
            self.bucket.download_fileobj(self.path, data)
            return json.loads(data.getvalue())
        except botocore.exceptions.ClientError as error:
            print(error)
            return {}

    def save(self, data: dict) -> None:
        output_data = io.BytesIO()
        output_data.write(json.dumps(data).encode("UTF-8"))
        output_data.seek(0)
        self.bucket.upload_fileobj(output_data, self.path)


class VersionMetaStorage(metaclass=Singleton):  # Singleton
    version_meta: dict

    def __init__(self):
        if settings.STORAGE_LOCATION == StorageLocation.LOCAL:
            warnings.warn("The storage location is set as local. Never mix it with other locations to avoid losing version data.")
            self.storage = LocalStorage(os.path.join(settings.CONFIG_DATA_FOLDER, settings.VERSION_META_FILE))
        elif settings.STORAGE_LOCATION == StorageLocation.AWS:
            print("The storage location is set as aws.")
            self.storage = S3Storage(
                os.path.join(settings.STORAGE_BUCKET_KEY, settings.VERSION_META_FILE))
        else:
            raise NotImplementedError
        storage_data = self.storage.load()
        if storage_data is None:
            storage_data = {}
        self.version_meta = storage_data

    def update(self, data: dict):
        self.version_meta.update(data)

    def set_data(self, new_version_meta: dict):
        self.version_meta = new_version_meta

    def as_dict(self) -> dict:
        return self.version_meta

    def sync(self):
        self.storage.save(self.version_meta)


# Used by KeyHandler, PackageHandler & Config to
# store data in a json file
class Storage(object):
    keypack: dict | None

    def __init__(self):
        """Loads & saves config file to file-system."""
        self.config_dir = os.path.join(os.getcwd(), settings.CONFIG_DATA_FOLDER)
        if not os.path.exists(self.config_dir):
            log.debug("Creating config dir")
            os.mkdir(self.config_dir)
        log.debug("Config Dir: %s", self.config_dir)
        self.filename = os.path.join(self.config_dir, settings.CONFIG_FILE_USER)
        log.debug("Config DB: %s", self.filename)
        self.db = JSONStore(self.filename)
        self.count = 0
        self.keypack = None
        self._load_db()

    def __getattr__(self, name):
        return self.__class__.__dict__.get(name)

    def __setattr__(self, name, value):
        setattr(self.__class__, name, value)

    def __delattr__(self, name):
        raise AttributeError("Cannot delete attributes!")

    def __getitem__(self, name):
        try:
            return self.__class__.__dict__[name]
        except KeyError:
            return self.__dict__[name]

    def __setitem__(self, name, value):
        setattr(Storage, name, value)

    def _load_db(self):
        """Loads database into memory."""
        for k, v in self.db:
            setattr(Storage, k, v)

        try:
            self.keypack = {
                "client": {
                    "offline_public": os.environ[settings.OFFLINE_PUBLIC_KEY],
                },
                "repo": {
                    "app_private": os.environ[settings.APP_PRIVATE_KEY],
                },
                "upload": {
                    "app_public": os.environ[settings.UPLOAD_APP_PUBLIC_KEY],
                    "signature": os.environ[settings.UPLOAD_SIGNATURE_KEY],
                }
            }
        except Exception:
            print("Unable to load keypacks from environment variables, using config.pyu instead")
            self.keypack = self.load(settings.CONFIG_DB_KEY_KEYPACK)

    def save(self, key, value):
        """Saves key & value to database

        Args:

            key (str): used to retrieve value from database

            value (obj): python object to store in database

        """
        setattr(Storage, key, value)
        for k, v in Storage.__dict__.items():
            self.db[k] = v
        log.debug("Syncing db to filesystem")
        self.db.sync()

    def load(self, key):
        """Loads value for given key

        Args:

            key (str): The key associated with the value you want
            form the database.

        Returns:

            Object if exists or else None
        """
        return self.__class__.__dict__.get(key)


def create_dynamodb_table():
    ddb_client = boto3.client('dynamodb', region_name=settings.STORAGE_BUCKET_REGION)
    DynamoDBLockClient.create_dynamodb_table(ddb_client)


if __name__ == '__main__':
    storage = VersionMetaStorage()
    original_dict = storage.as_dict()
    print(original_dict)
    original_dict["new_entry"] = original_dict["new_entry"] + 1
    print(storage.as_dict())
    storage.sync()
    time.sleep(60)
