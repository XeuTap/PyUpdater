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
from __future__ import unicode_literals
import logging

from pyupdater import settings

log = logging.getLogger(__name__)


class Config(dict):
    def __init__(self, *args, **kwargs):
        super(Config, self).__init__(*args, **kwargs)
        self.__dict__ = self
        self._set_default()

    def _set_default(self):
        config_template = {
            # If left None "PyUpdater App" will be used
            "APP_NAME": settings.GENERIC_APP_NAME,
            # path to place client config
            "CLIENT_CONFIG_PATH": settings.DEFAULT_CLIENT_CONFIG,
            # Company/Your name
            "COMPANY_NAME": settings.GENERIC_APP_NAME,
            "PLUGIN_CONFIGS": {},
            # Support for patch updates
            "UPDATE_PATCHES": True,
            # Max retries for downloads
            "MAX_DOWNLOAD_RETRIES": 3,
            # HTTP TIMEOUT
            "HTTP_TIMEOUT": 30,
        }
        self.update(config_template)

    def from_object(self, obj):
        # Updates the values from the given object

        # Args:

        #     obj (instance): Object with config attributes

        # Objects are classes.

        # Just the uppercase variables in that object are stored in the config.
        # Example usage::

        #     from yourapplication import default_config
        #     app.config.from_object(default_config())
        for key in dir(obj):
            if key.isupper():
                self[key] = getattr(obj, key)


# Loads &  saves config file
