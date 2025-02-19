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
import io
import logging
import os
import shutil
import subprocess
import time
import traceback
import uuid
import sys
import tarfile
import threading
import zipfile
import ctypes
from pathlib import Path
from typing import Iterable

from dsdev_utils.helpers import Version, VersionFormat
from dsdev_utils.paths import ChDir, get_mac_dot_app_dir, remove_any
from dsdev_utils.system import get_system

from pyupdater import settings
from pyupdater.client.downloader import FileDownloader, get_hash
from pyupdater.client.patcher import Patcher
from pyupdater.core.package_handler.package import remove_previous_versions
from pyupdater.utils.exceptions import ClientError

log = logging.getLogger()


def requires_admin(path):  # pragma: no cover
    """Check if a dir or a file requires admin permissions write/change."""
    if os.path.isdir(path):
        return dir_requires_admin(path)
    elif os.path.isfile(path):
        return file_requires_admin(path)
    else:
        raise ValueError("requires_admin needs dir or file.")


def file_requires_admin(file_path):  # pragma: no cover
    """Check if a file requires admin permissions change."""
    try:
        with open(file_path, "a"):
            pass
        return False
    except PermissionError:
        return True


def dir_requires_admin(_dir):  # pragma: no cover
    """
    Check if a dir required admin permissions to write.
    If dir is a file test it's directory.
    """
    _dir = os.path.dirname(_dir)
    dummy_filepath = os.path.join(_dir, str(uuid.uuid4()))
    try:
        with open(dummy_filepath, "w"):
            pass
        remove_any(dummy_filepath)
        return False
    except IOError:
        return True


def win_hide_file(file):  # pragma: no cover
    ret = ctypes.windll.kernel32.SetFileAttributesW(file, 0x02)
    if not ret:
        # WinError will automatically grab the relevant code and message
        raise ctypes.WinError()


def win_unhide_file(file):  # pragma: no cover
    attrs = ctypes.windll.kernel32.GetFileAttributesW(file)
    if attrs == -1:
        raise ctypes.WinError()
    ret = ctypes.windll.kernel32.SetFileAttributesW(file, attrs & (~0x02))
    if not ret:
        raise ctypes.WinError()


def win_run(command: str, args: Iterable = None, admin=False):  # pragma: no cover
    if args is None:
        args = []
    """
    In windows run a command, optionally as admin.
    """
    if admin:
        import win32con
        from win32com.shell.shell import ShellExecuteEx # noqa
        from win32com.shell import shellcon # noqa

        ShellExecuteEx(
            nShow=win32con.SW_SHOWNORMAL,
            fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
            lpVerb="runas",
            lpFile=command,
            lpParameters=" ".join('"{}"'.format(arg) for arg in args),
        )
    else:
        subprocess.Popen([command] + args)

def get_version(name, plat, channel, easy_data, strict, limit_date_ts=0.0):
    target_version = None

    version_options = []
    alpha_versions = []
    beta_versions = []
    stable_versions = []
    for version_str, version_data in easy_data["updates"][name].items():
        version_date_ts = version_data[plat].get("date", 0)
        version = Version(version_str, format=VersionFormat.FULL)
        if version_date_ts and limit_date_ts and version_date_ts > limit_date_ts:
            continue
        if version.channel == "alpha":
            alpha_versions.append(version)
        elif version.channel == "beta":
            beta_versions.append(version)
        elif version.channel == "stable":
            stable_versions.append(version)
        else:
            log.debug("Failed to fetch version channel, {}".format(str(version)))
            continue

    log.debug("Alpha str: %s", str(max(alpha_versions)))
    log.debug("Beta str: %s", str(max(beta_versions)))
    log.debug("Stable str: %s", str(max(stable_versions)))

    if strict is False:
        return max(version_options)

    if alpha_versions is True and channel == "alpha":
        target_version = max(alpha_versions)

    if beta_versions is True and channel == "beta":
        target_version = max(beta_versions)

    if stable_versions is True and channel == "stable":
        target_version = max(stable_versions)

    if target_version is not None:
        log.debug("Highest version: %s", target_version)
        return target_version
    else:
        log.info('No updates for "%s" on %s exists', name, plat)
        return target_version


def get_highest_version(name, plat, channel, easy_data, strict):
    # Parses version file and returns the highest version number.
    #
    #   Args:
    #
    #      name (str): name of file to search for updates
    #
    #      plat (str): the platform we are requesting for
    #
    #      channel (str): the release channel
    #
    #      easy_data (dict): data file to search
    #
    #      strict (bool): specify whether or not to take the channel
    #                     into consideration
    #
    #   Returns:
    #
    #      (str) Highest version number

    # We grab all keys and return the version corresponding to the
    # channel passed to this function
    version_key_alpha = "{}*{}*{}*{}".format("latest", name, "alpha", plat)
    version_key_beta = "{}*{}*{}*{}".format("latest", name, "beta", plat)
    version_key_stable = "{}*{}*{}*{}".format("latest", name, "stable", plat)
    version = None

    version_options = []

    alpha_available = False
    raw_alpha_ver = easy_data.get(version_key_alpha)
    if isinstance(raw_alpha_ver, dict):
        alpha_str = raw_alpha_ver["version"]
    elif isinstance(raw_alpha_ver, str):
        alpha_str = raw_alpha_ver
    else:
        alpha_str = None
    if alpha_str is not None:
        log.debug("Alpha str: %s", alpha_str)
        alpha = Version(alpha_str, format=VersionFormat.FULL)
        version_options.append(alpha)
        alpha_available = True
    beta_available = False
    raw_beta_ver = easy_data.get(version_key_beta)
    if isinstance(raw_beta_ver, dict):
        beta_str = raw_beta_ver["version"]
    elif isinstance(raw_beta_ver, str):
        beta_str = raw_beta_ver
    else:
        beta_str = None
    if beta_str is not None:
        log.debug("Beta str: %s", beta_str)
        beta = Version(beta_str, format=VersionFormat.FULL)
        version_options.append(beta)
        beta_available = True

    raw_stable_ver = easy_data.get(version_key_stable)
    if isinstance(raw_stable_ver, dict):
        stable_str = raw_stable_ver["version"]
    elif isinstance(raw_stable_ver, str):
        stable_str = raw_stable_ver
    else:
        stable_str = None
    stable_available = False
    if stable_str is not None:
        log.debug("Stable str: %s", stable_str)
        stable = Version(stable_str, format=VersionFormat.FULL)
        version_options.append(stable)
        stable_available = True

    if strict is False:
        return max(version_options)

    if alpha_available is True and channel == "alpha":
        version = alpha

    if beta_available is True and channel == "beta":
        version = beta

    if stable_available is True and channel == "stable":
        version = stable

    if version is not None:
        log.debug("Highest version: %s", version)
        return version
    else:
        log.info('No updates for "%s" on %s exists', name, plat)
        return version


def gen_user_friendly_version(internal_version):
    channel = {0: "Alpha", 1: "Beta"}
    v = list(map(int, internal_version.split(".")))

    # 1.2
    version = "{}.{}".format(v[0], v[1])
    if v[2] != 0:
        # 1.2.1
        version += ".{}".format(v[2])
    if v[3] != 2:
        # 1.2.1 Alpha
        version += " {}".format(channel[v[3]])
        if v[4] != 0:
            version += " {}".format(v[4])

    return version


class UpdateStrategy:  # pragma: no cover
    """Enum representing the update strategies available"""

    DEFAULT = (
        "overwrite"  # The default strategy to use.  Currently is the overwrite strategy
    )
    OVERWRITE = "overwrite"  # Overwrites the binary in place
    RENAME = "rename"  # Renames the binary.  Only available for Windows single file bundled executables


class Restarter(object):  # pragma: no cover
    def __init__(self, current_app, **kwargs):
        self.current_app = current_app
        self.name = kwargs.get("name", "")
        self.strategy = kwargs.get("strategy", UpdateStrategy.DEFAULT)
        log.debug("Current App: %s", self.current_app)
        self.is_win = sys.platform == "win32"
        self.updater_name = "updater.exe"
        self.check_permissions = kwargs.get("check_permissions", False)
        if self.is_win is True and self.strategy == UpdateStrategy.OVERWRITE:
            self.data_dir = kwargs.get("data_dir")
            self.bat_file = os.path.join(self.data_dir, "update.bat")
            self.vbs_file = os.path.join(self.data_dir, "invis.vbs")
            self.update_folder = kwargs.get("update_folder")
            self.update_filename = kwargs.get("update_filename")
            self.updated_app = kwargs.get("updated_app")
            log.debug("Restart script dir: %s", self.data_dir)
            log.debug("Update path: %s", self.updated_app)

    def process(self, win_restart=True):
        if self.is_win and self.strategy == UpdateStrategy.OVERWRITE:
            is_folder = os.path.isdir(self.updated_app)
            needs_admin = requires_admin(os.path.dirname(self.updated_app))
            is_file = os.path.isfile(self.updated_app)
            if is_file:
                needs_admin = needs_admin or requires_admin(self.current_app)
            log.debug("Admin required to update={}".format(needs_admin))
            self._win_overwrite(restart=win_restart, one_dir=is_folder)
        else:
            self._restart()

    def _restart(self):
        os.execl(self.current_app, self.name, *sys.argv[1:])

    def _win_overwrite(self, restart: bool, override_check_permissions: bool = None, one_dir: bool = False):
        info_file = os.path.join(os.environ.get("APPDATA"), "extract_info_2.txt")
        check_permissions = override_check_permissions
        if override_check_permissions is None:
            check_permissions = self.check_permissions
        compiled_executable_path = os.path.join(str(Path(sys.executable).parent), self.updater_name)
        if hasattr(sys, '_MEIPASS'):
            meipass = sys._MEIPASS
        else:
            meipass = ""
        pyinstaller_internal_path = os.path.join(meipass, self.updater_name)
        if os.path.isfile(compiled_executable_path):
            updater_filepath = compiled_executable_path
        elif os.path.isfile(pyinstaller_internal_path):
            updater_filepath = pyinstaller_internal_path
        else:
            updater_filepath = None
        if updater_filepath:
            updater_args = [
                os.path.dirname(self.current_app),
                os.path.join(self.update_folder, self.update_filename),
                self.current_app,
            ]
            if not check_permissions:
                updater_args.append("--skip-folder-check")
            if not restart:
                updater_args.append("--disable-executable")
            log.debug("Starting update using updater")
            if os.path.isfile(info_file):
                os.remove(info_file)
            with open(info_file, "w") as file:
                file.write("Starting update using updater\n")
            updater_folder = os.path.join(self.data_dir, settings.UPDATER_FOLDER)
            os.makedirs(updater_folder, exist_ok=True)
            temp_updater_filepath = os.path.join(updater_folder, self.updater_name)
            if os.path.isfile(temp_updater_filepath):
                os.remove(temp_updater_filepath)
            shutil.copyfile(updater_filepath, temp_updater_filepath)
            log.debug("Starting update process", temp_updater_filepath, updater_args)
            win_run(temp_updater_filepath, updater_args)
        else:
            self._extract_update()
            self._create_update_script(restart=restart, check_permissions=check_permissions, one_dir=one_dir)
            log.debug("Starting update using batch file")
            win_run(self.bat_file, admin=False)
        log.debug("Finishing the process")
        os._exit(0)

    def _extract_update(self):
        os.makedirs(self.update_folder, exist_ok=True)
        with ChDir(self.update_folder):
            log.debug("Extracting Update")
            archive_ext = os.path.splitext(self.update_filename)[1].lower()

            if archive_ext == ".zip":
                try:
                    with zipfile.ZipFile(self.update_filename, "r") as zfile:
                        # Extract update file to current
                        # directory.
                        zfile.extractall()
                except Exception as err:  # pragma: no cover
                    log.debug(err, exc_info=True)
                    raise ClientError("Error reading zip file", expected=True)

    def _create_update_script(self,
                              restart: bool = True,
                              check_permissions: bool = True,
                              one_dir: bool = False) -> None:
        start_app = ""
        if restart:
            start_app = f'start "" "{self.current_app}"\n'
        wait_for_access = """
        ping 127.0.0.1 -n 5 -w 1000 > NUL
        goto accessGranted\n"""
        if check_permissions:
            wait_for_access = """:start
timeout /T 1 >>NUL
echo %%a%%

if %%a%% GEQ 30 (
goto stop
)

set /A a=%%a%%+1
if exist %%observable_file%% (
2>nul (
>> %%observable_file%%  (call )
) && (goto accessGranted) || (goto start) ) else ( exit )

:stop
echo "ACCESS TIMEOUT" >> %%appdata%%/extract_info_2.txt
goto end"""
        extract_method = """robocopy "%(src_dir)s" "%(destination_dir)s" /e /move /V /xf %(name)s*.zip >> %%appdata%%/extract_info_2.txt""" % {
            "src_dir": os.path.dirname(self.updated_app),
            "destination_dir": os.path.dirname(self.current_app),
            "name": self.name,
        }
        if one_dir:
            extract_method = """robocopy "%(src_dir)s" "%(destination_dir)s" /e /move /V > %%appdata%%/extract_info_1.txt""" % {
                "src_dir": self.updated_app,
                "destination_dir": self.current_app,
            }
        with io.open(self.bat_file, "w", encoding="utf-8") as bat:
            bat.write(
                """
@ECHO off
chcp 65001
echo Updating to latest version... > %%appdata%%/extract_info_2.txt
set a=1
set observable_file="%(current_app)s"

%(wait_for_access)s

:accessGranted
echo %%a%%
echo "FILE AVAILABLE" >> %%appdata%%/extract_info_2.txt
%(extract_method)s
echo restarting... >> %%appdata%%/extract_info_2.txt
%(start_app)s
goto end


:end
DEL "%%~f0"
                """ % {
                    "current_app": self.current_app,
                    "start_app": start_app,
                    "wait_for_access": wait_for_access,
                    "extract_method": extract_method,
                })


class LibUpdate(object):
    """Used to update library files used by an application. This object is
    returned by pyupdater.client.Client.update_check

    ######Args:

    data (dict): Info dict
    """

    def __init__(self, data=None, proxy=None, ssl_cert=None):
        if data is None:
            return

        self.proxy = proxy
        self.ssl_cert = ssl_cert
        # A key used in the version meta data dictionary
        self._updates_key = settings.UPDATES_KEY

        # The current directory of the running executable
        self._current_app_dir = os.path.dirname(sys.executable)

        # The status of the download. Once downloaded this will be True
        self._download_status = False

        # If user is using async download this will be True.
        # Future calls to an download methods will not run
        # until the current download is complete. Which will
        # set this back to False.
        self._is_downloading = False

        # Used with the version property.
        # Returns a user friendly version string
        self._version = ""

        # Dictionary of config variables
        self.init_data = data

        # List of urls used to look for meta data & updates
        self.update_urls = data.get("update_urls")

        # The name of the asset we are targeting. Provided by user
        # in update_check
        self.name = data.get("name")

        # The APP_NAME  specified in the client_config.py
        self.app_name = data.get("app_name")

        # The version of the current asset
        self.current_version = data.get("version")

        # A special dictionary that allows getting nested values by
        # providing a key in the form of "this*is*a*deep*key".
        self.easy_data = data.get("easy_data")

        # Raw form of easy_data
        self.json_data = data.get("json_data")

        # The directory used to store files needed for the restart process
        # on windows
        self.data_dir = data.get("data_dir")

        # The platform we are targeting
        self.platform = data.get("platform")

        # The channel we are targeting
        self.channel = data.get("channel", "stable")

        # How strict to treat the channel requirement
        self.strict = data.get("strict")

        # Progress callbacks
        self.progress_hooks = data.get("progress_hooks")

        # The folder on the end users system which hold meta data & updates
        self.update_folder = os.path.join(self.data_dir, settings.UPDATE_FOLDER)

        # Weather or not the verify the https connection
        self.verify = data.get("verify", True)

        # Extra headers
        self.headers = data.get("headers")

        # The amount of times to retry a url before giving up
        self.max_download_retries = data.get("max_download_retries")

        # HTTP Timeout
        self.http_timeout = data.get("http_timeout")

        self.downloader = data.get("downloader")

        # The update strategy to use
        self.strategy = data.get("strategy", UpdateStrategy.DEFAULT)

        # The latest version available
        self.latest = data.get("target_version")

        # The name of the current versions update archive.
        # Will be used to check if the current archive is available for a
        # patch update
        cv = self.current_version
        self._current_archive_name = LibUpdate._get_filename(
            self.name, cv, self.platform, self.easy_data
        )

        # Get filename of latest versions update archive
        # self.latest = Version(self.latest, format=VersionFormat.FULL)

        self.filename = LibUpdate._get_filename(
            self.name, str(self.latest), self.platform, self.easy_data
        )
        assert self.filename is not None

        # Used to remove version earlier than the current.
        self.cleanup()

    @property
    def version(self):
        """Generates a user friendly version string

        ######Returns (str): User friendly version string
        """
        if self._version == "":
            self._version = gen_user_friendly_version(str(self.latest))
        return self._version

    def is_downloaded(self):
        """Used to check if update has been downloaded.

        ######Returns (bool):

            True - File is already downloaded.

            False - File has not been downloaded.
        """
        if self._is_downloading is True:
            return False
        return self._is_downloaded()

    def download(self, background=False):
        """Downloads update

        ######Args:

            background (bool): Perform download in background thread
        """
        if background is True:
            if self._is_downloading is False:
                self._is_downloading = True
                threading.Thread(target=self._download).start()
        else:
            if self._is_downloading is False:
                self._is_downloading = True
                return self._download()

    # def extract(self):
    #     """Will extract the update from its archive to the update folder.
    #     If updating a lib you can take over from there. If updating
    #     an app this call should be followed by method "restart" to
    #     complete update.
    #
    #     ######Returns:
    #
    #         (bool) True - Extract successful. False - Extract failed.
    #     """
    #     # if get_system() == "win":  # Tested elsewhere
    #     #    log.debug("Only supported on Unix like systems")
    #     #    return False
    #     try:
    #         self._extract_update()
    #     except ClientError as err:
    #         print(traceback.format_exc())
    #         log.debug(err, exc_info=True)
    #         return False
    #     return True

    @staticmethod
    def _get_filename(name, version, platform, easy_data):
        """Gets full filename for given name & version combo

        Args:

            name (str): Name of file

            version (str): Version of file to get full filename for

            easy_data (dict): Data file to search

        Returns:

            (str) Filename with extension
        """
        filename_key = "{}*{}*{}*{}*{}".format(
            settings.UPDATES_KEY, name, version, platform, "filename"
        )
        filename = easy_data.get(filename_key)

        log.debug("Filename for %s-%s: %s", name, version, filename)
        return filename

    def _download(self):
        if self.name is not None:
            if self._is_downloaded() is True:  # pragma: no cover
                self._download_status = True
            else:
                log.debug("Starting patch download")
                patch_success = False
                if self.channel == "stable":
                    patch_success = self._patch_update()
                # Tested elsewhere
                if patch_success:  # pragma: no cover
                    self._download_status = True
                    log.debug("Patch download successful")
                else:
                    log.debug("Patch update failed")
                    log.debug("Starting full download")
                    update_success = self._full_update()
                    if update_success:
                        self._download_status = True
                        log.debug("Full download successful")
                    else:  # pragma: no cover
                        log.debug("Full download failed")

        self._is_downloading = False
        return self._download_status

    def _verify_update(self) -> None:
        os.makedirs(self.update_folder, exist_ok=True)
        with ChDir(self.update_folder):
            if not os.path.exists(self.filename):
                log.debug("File does not exists")
                raise ClientError("File does not exists", expected=True)

            if self._verify_file_hash():
                log.debug("Extracting Update")
                archive_ext = os.path.splitext(self.filename)[1].lower()
                # if archive_ext not in [".gz", ".bz2", ".zip"]:
                if archive_ext not in [".zip"]:
                    raise ClientError("Unknown file type")
            else:
                raise ClientError("Update archive is corrupt")

    # def _extract_update(self):
    #     with ChDir(self.update_folder):
    #         if not os.path.exists(self.filename):
    #             log.debug("File does not exists")
    #             raise ClientError("File does not exists", expected=True)
    #
    #         if not os.access(self.filename, os.R_OK):
    #             raise ClientError("Permissions Error", expected=True)
    #
    #         if self._verify_file_hash():
    #             log.debug("Extracting Update")
    #             archive_ext = os.path.splitext(self.filename)[1].lower()
    #
    #             if archive_ext in [".gz", ".bz2"]:
    #                 try:
    #                     mode = "r:{}".format(archive_ext[1:])
    #                     with tarfile.open(self.filename, mode) as tfile:
    #                         # Extract file update to current
    #                         # directory.
    #                         tfile.extractall()
    #                 except Exception as err:  # pragma: no cover
    #                     log.debug(err, exc_info=True)
    #                     raise ClientError("Error reading gzip file", expected=True)
    #             elif archive_ext == ".zip":
    #                 try:
    #                     with zipfile.ZipFile(self.filename, "r") as zfile:
    #                         # Extract update file to current
    #                         # directory.
    #                         zfile.extractall()
    #                 except Exception as err:  # pragma: no cover
    #                     log.debug(err, exc_info=True)
    #                     raise ClientError("Error reading zip file", expected=True)
    #             else:
    #                 raise ClientError("Unknown file type")
    #         else:
    #             raise ClientError("Update archive is corrupt")

    def _get_file_hash_from_manifest(self):
        hash_key = "{}*{}*{}*{}*{}".format(
            self._updates_key, self.name, self.latest, self.platform, "file_hash"
        )
        return self.easy_data.get(hash_key)

    # Must be called from directory where file is located
    def _verify_file_hash(self):
        if not os.path.exists(self.filename):
            log.error("File does not exist")
            return False

        file_hash = self._get_file_hash_from_manifest()
        try:
            with open(self.filename, "rb") as f:
                data = f.read()
        except Exception as err:
            log.error(err, exc_info=True)
            return False

        if file_hash == get_hash(data):
            return True
        else:
            return False

    # Checks if latest update is already downloaded
    def _is_downloaded(self):
        # Comparing file hashes to ensure security
        os.makedirs(self.update_folder, exist_ok=True)
        with ChDir(self.update_folder):
            verified = self._verify_file_hash()

        return verified

    # Handles patch updates
    def _patch_update(self):  # pragma: no cover
        log.debug("Starting patch update")
        # The current version is not in the version manifest
        if self._current_archive_name is None:
            return False

        # Just checking to see if the zip for the current version is
        # available to patch If not we'll fall back to a full binary download
        if not os.path.exists(
                os.path.join(self.update_folder, self._current_archive_name)
        ):
            log.debug(
                "%s got deleted. No base binary to start patching " "form",
                self._current_archive_name,
            )
            return False

        # Initialize Patch object with all required information
        p = Patcher(
            current_version=self.current_version,
            latest_version=self.latest,
            update_folder=self.update_folder,
            **self.init_data
        )

        # Returns True if everything went well
        # If False, fall back to a full update
        try:
            rv = p.start()
        except Exception as err:
            log.debug(err, exc_info=True)
            rv = False

        return rv

    def _full_update(self):
        log.debug("Starting full update")
        file_hash = self._get_file_hash_from_manifest()
        os.makedirs(self.update_folder, exist_ok=True)
        with ChDir(self.update_folder):
            log.debug("Downloading update...")
            if self.downloader:
                fd = self.downloader(
                    self.filename, self.update_urls, hexdigest=file_hash
                )
            else:
                fd = FileDownloader(
                    self.filename,
                    self.update_urls,
                    hexdigest=file_hash,
                    verify=self.verify,
                    progress_hooks=self.progress_hooks,
                    max_download_retries=self.max_download_retries,
                    headers=self.headers,
                    http_timeout=self.http_timeout,
                    proxy=self.proxy,
                    ssl_cert=self.ssl_cert,
                )
            result = fd.download_verify_write()
            if result:
                log.debug("Download Complete")
                return True
            else:  # pragma: no cover
                log.debug("Failed To Download Latest Version")
                return False

    def cleanup(self):
        """Cleans up old update archives for this app or asset"""
        log.debug("Beginning removal of old updates")
        if self._current_archive_name is not None:
            rpv = remove_previous_versions
            path_to_current_archive = os.path.join(
                self.update_folder, self._current_archive_name
            )
            t = threading.Thread(
                target=rpv, args=(self.update_folder, path_to_current_archive)
            )
            t.start()


class AppUpdate(LibUpdate):  # pragma: no cover
    """Used to update an application. This object is returned by
    pyupdater.client.Client.update_check

    Args:

        data (dict): Info dict
    """

    def __init__(self, data, **kwargs):
        self._is_win = get_system() == "win"
        super(AppUpdate, self).__init__(data, **kwargs)

    def extract_restart(self, check_permissions: bool = True):
        """Will extract the update, overwrite the current binary,
        then restart the application using the updated binary."""
        try:
            self._verify_update()

            if self._is_win:
                if self.strategy == UpdateStrategy.RENAME:
                    self._win_rename_restart()
                else:
                    self._win_overwrite_restart(check_permissions)
            else:
                raise NotImplementedError
                # self._overwrite()
                # self._restart()
        except ClientError as err:
            log.error(err, exc_info=True)

    def extract_overwrite(self, check_permissions: bool = True):
        """Will extract the update then overwrite the current binary"""
        try:
            self._verify_update()
            if self._is_win:
                if self.strategy == UpdateStrategy.RENAME:
                    self._win_rename()
                else:
                    self._win_overwrite(check_permissions)
            else:
                self._overwrite()
        except ClientError as err:
            log.debug(err, exc_info=True)

    def _overwrite(self):
        # Unix: Overwrites the running applications binary
        if get_system() == "mac":
            if self._current_app_dir.endswith("MacOS") is True:
                log.debug("Looks like we're dealing with a Mac Gui")
                temp_dir = get_mac_dot_app_dir(self._current_app_dir)
                self._current_app_dir = temp_dir

        app_update = os.path.join(self.update_folder, self.name)

        # Must be dealing with Mac .app application
        if not os.path.exists(app_update) and sys.platform == "darwin":
            app_update += ".app"

        log.debug("Update Location:\n%s", os.path.dirname(app_update))
        log.debug("Update Name: %s", os.path.basename(app_update))

        current_app = os.path.join(self._current_app_dir, self.name)

        # Must be dealing with Mac .app application
        if not os.path.exists(current_app):
            current_app += ".app"

        log.debug("Current App location:\n\n%s", current_app)

        # Remove current app to prevent errors when moving
        # update to new location
        # if update_app is a directory, then we are updating a directory
        if os.path.isdir(app_update):
            if os.path.isdir(current_app):
                shutil.rmtree(current_app)
            else:
                shutil.rmtree(os.path.dirname(current_app))

        if os.path.exists(current_app):
            remove_any(current_app)

        log.debug("Moving app to new location:\n\n%s", self._current_app_dir)
        shutil.move(app_update, self._current_app_dir)

    def _restart(self):
        log.debug("Restarting")
        current_app = os.path.join(self._current_app_dir, self.name)
        if get_system() == "mac":
            # Must be dealing with Mac .app application
            if not os.path.exists(current_app):
                log.debug("Must be a .app bundle")
                current_app += ".app"
                mac_app_binary_dir = os.path.join(current_app, "Contents", "MacOS")
                _file = os.listdir(mac_app_binary_dir)

                # We are making an assumption here that only 1
                # executable will be in the MacOS folder.
                current_app = os.path.join(mac_app_binary_dir, sys.executable)

        r = Restarter(current_app, name=self.name)
        r.process()

    def _win_rename(self):
        exe_name = self.name + ".exe"
        current_app = os.path.join(self._current_app_dir, exe_name)
        old_exe_name = exe_name + ".old"
        old_app = os.path.join(self._current_app_dir, old_exe_name)
        updated_app = os.path.join(self.update_folder, exe_name)

        # detect if is a folder
        if os.path.exists(os.path.join(self.update_folder, self.name)):
            raise ClientError(
                "The rename strategy is only supported for one file bundled executables"
            )

        # Remove the old app from previous updates
        if os.path.exists(old_app):
            os.unlink(old_app)

        # On Windows, it's possible to rename a currently running exe file
        os.rename(current_app, old_app)

        # Any operation from here forward will require rollback on failure
        try:
            os.rename(updated_app, current_app)
        except OSError as e:
            log.error("Failed to move updated app into position, rolling back")
            # Rollback strategy: move current app back into position
            if os.path.exists(current_app):
                os.unlink(current_app)
            os.rename(old_app, current_app)
            raise e

        try:
            # Hide the old app
            win_hide_file(old_app)
        except WindowsError as e:
            # Failed to hide file, which is fine - we can still continue
            log.error("Failed to hide file")

        return old_app, current_app, updated_app

    def _win_rename_restart(self):
        old_app, current_app, updated_app = self._win_rename()

        try:
            r = Restarter(current_app, name=self.name, strategy=UpdateStrategy.RENAME)
            r.process()
        except OSError as e:
            # Raised by os.execl
            log.error("Failed to launch updated app, rolling back")
            # Rollback strategy: unhide old app, delete current app, move old app back
            try:
                win_unhide_file(old_app)
            except WindowsError:
                # Better to stay hidden than to just fail at this point
                log.error("Could not unhide file in rollback process")
            # Rename does not overwrite on Windows, so will need to unlink
            os.unlink(current_app)
            # Move old app back
            os.rename(old_app, current_app)
            raise e

    def _win_overwrite(self, check_permissions: bool):
        # Windows: Moves update to current directory of running
        #                 application then restarts application using
        #                 new update.
        exe_name = self.name + ".exe"
        current_app = os.path.join(self._current_app_dir, exe_name)
        updated_app = os.path.join(self.update_folder, exe_name)

        # detect if is a folder
        if os.path.exists(os.path.join(self.update_folder, self.name)):
            current_app = self._current_app_dir
            updated_app = os.path.join(self.update_folder, self.name)

        update_info = dict(
            data_dir=self.data_dir,
            updated_app=updated_app,
            update_folder=self.update_folder,
            update_filename=self.filename,
            name=self.name,
            check_permissions=check_permissions,
        )
        r = Restarter(current_app, **update_info)
        r.process(win_restart=False)

    def _win_overwrite_restart(self, check_permissions: bool):
        # Windows: Moves update to current directory of running
        #          application then restarts application using
        #          new update.

        exe_name = self.name + ".exe"
        current_app = os.path.join(self._current_app_dir, exe_name)
        updated_app = os.path.join(self.update_folder, exe_name)

        # detect if is a folder
        if os.path.exists(os.path.join(self.update_folder, self.name)):
            current_app = self._current_app_dir
            updated_app = os.path.join(self.update_folder, self.name)

        update_info = dict(
            data_dir=self.data_dir,
            updated_app=updated_app,
            name=self.name,
            update_folder=self.update_folder,
            update_filename=self.filename,
            check_permissions=check_permissions,
        )
        r = Restarter(current_app, **update_info)
        r.process()
