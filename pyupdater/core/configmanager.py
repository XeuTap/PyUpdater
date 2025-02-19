from __future__ import unicode_literals

import os

from pyupdater import settings
from pyupdater.utils.config import Config, log
from pyupdater.utils.storage import Storage


class ConfigManager(object):
    def __init__(self):
        self.cwd = os.getcwd()
        self.db = Storage()
        self.config_key = settings.CONFIG_DB_KEY_APP_CONFIG

    # Loads config from database (json file)
    def load_config(self):
        config_data = self.db.load(self.config_key)
        if config_data is None:
            config_data = {}
        config = Config()
        for k, v in config_data.items():
            config[k] = v
        config.DATA_DIR = os.getcwd()
        return config

    def get_app_name(self):
        config = self.load_config()
        return config.APP_NAME

    # Saves config to database (json file)
    def save_config(self, obj):
        log.debug("Saving Config")
        self.db.save(self.config_key, obj)
        log.debug("Config saved")
        self.write_config_py(obj)
        log.debug("Wrote client config")

    # Writes client config to client_config.py
    def write_config_py(self, obj):
        keypack_data = self.db.keypack
        if keypack_data is None:
            log.debug("*** Keypack data is None ***")
            public_key = None
        else:
            public_key = keypack_data["client"]["offline_public"]

        filename = os.path.join(self.cwd, *obj.CLIENT_CONFIG_PATH)
        attr_str_format = "    {} = '{}'\n"
        attr_format = "    {} = {}\n"

        log.debug("Writing client_config.py")
        with open(filename, "w") as f:
            f.write("class ClientConfig(object):\n")

            log.debug("Adding PUBLIC_KEY to client_config.py")
            f.write(attr_str_format.format("PUBLIC_KEY", public_key))

            if hasattr(obj, "APP_NAME"):
                log.debug("Adding APP_NAME to client_config.py")
                f.write(attr_str_format.format("APP_NAME", obj.APP_NAME))

            if hasattr(obj, "COMPANY_NAME"):
                log.debug("Adding COMPANY_NAME to client_config.py")
                f.write(attr_str_format.format("COMPANY_NAME", obj.COMPANY_NAME))

            if hasattr(obj, "HTTP_TIMEOUT"):
                log.debug("Adding HTTP_TIMEOUT to cilent_config.py")
                f.write(attr_format.format("HTTP_TIMEOUT", obj.HTTP_TIMEOUT))

            if hasattr(obj, "MAX_DOWNLOAD_RETRIES"):
                log.debug("Adding MAX_DOWNLOAD_RETRIES to client_config.py")
                f.write(
                    attr_format.format("MAX_DOWNLOAD_RETRIES", obj.MAX_DOWNLOAD_RETRIES)
                )

            if hasattr(obj, "UPDATE_URLS"):
                log.debug("Adding UPDATE_URLS to client_config.py")
                f.write(attr_format.format("UPDATE_URLS", obj.UPDATE_URLS))
