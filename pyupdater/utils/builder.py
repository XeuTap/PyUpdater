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
import re
import shutil
import sys
import time

from PyInstaller import isolated
from PyInstaller.building.datastruct import normalize_toc
from stdlib_list import stdlib_list

STDLIB_MODULES = stdlib_list('.'.join([str(v) for v in sys.version_info[0:2]]))
from pathlib import Path

from PyInstaller.archive import pyz_crypto
from PyInstaller.building.build_main import Analysis, find_binary_dependencies
from PyInstaller.building.utils import add_suffix_to_extension, compile_pymodule, format_binaries_and_datas, \
    postprocess_binaries_toc_pywin32
from PyInstaller.compat import BINARY_MODULE_TYPES, PURE_PYTHON_MODULE_TYPES, PY3_BASE_MODULES
from PyInstaller.config import CONF
from PyInstaller.utils.cliutils.makespec import generate_parser
from dsdev_utils.exceptions import VersionError
from dsdev_utils.helpers import Version
from dsdev_utils.paths import ChDir, remove_any
from dsdev_utils.system import get_system
from PyInstaller.__main__ import run as pyi_build

from pyupdater import settings
from pyupdater.hooks import get_hook_dir
from pyupdater.utils.pyinstaller_compat import pyi_makespec, ArgSaver
from pyupdater.utils import create_asset_archive, make_archive
from pyupdater.utils.config import ConfigManager

log = logging.getLogger(__name__)


class Builder(object):  # pragma: no cover
    """Wrapper for Pyinstaller with some extras. After building
    executable with pyinstaller, Builder will create an archive
    of the executable.

    Args:

        args (list): Args specific to PyUpdater

        pyi_args (list): Args specific to Pyinstaller
    """

    def __init__(self, args, pyi_args):
        # We only need to grab appname
        cm = ConfigManager()
        self.app_name = cm.get_app_name()
        self.args = args
        self.app_info, self.pyi_args = Builder._check_input_file(pyi_args)

    def _build_args(self, spec_file_path):
        build_args = []
        if self.args.clean is True:
            build_args.append("--clean")

        if self.args.pyi_log_info is False:
            build_args.append("--log-level=ERROR")

        build_args.append("--distpath={}".format(self.new_dir))
        build_args.append("--workpath={}".format(self.work_dir))
        build_args.append("-y")
        build_args.append(spec_file_path)

        log.debug("Build cmd: %s", " ".join([b for b in build_args]))
        build_args = [str(x) for x in build_args]
        return build_args

    # Creates & archives executable
    def build(self):
        start = time.time()

        # Check for spec file or python script
        self._setup()

        temp_name = get_system()
        spec_file_path = os.path.join(self.spec_dir, temp_name + ".spec")

        # Spec file used instead of python script
        if self.app_info["type"] == "spec":
            spec_file_path = self.app_info["name"]
        else:
            # Creating spec file from script
            self._make_spec(temp_name)

        build_args = self._build_args(spec_file_path)

        # Build executable
        self._build(spec_file_path, build_args)

        self._override_dependencies(spec_file_path)
        # Archive executable
        self._archive(temp_name)
        finished = time.time() - start
        log.info("Build finished in {:.2f} seconds.".format(finished))

    def make_spec(self):
        temp_name = get_system()
        self._make_spec(temp_name, spec_only=True)

    def _setup(self):
        # Create required directories
        self.pyi_dir = os.path.join(os.getcwd(), settings.USER_DATA_FOLDER)
        self.new_dir = os.path.join(self.pyi_dir, "new")
        self.build_dir = os.path.join(os.getcwd(), settings.CONFIG_DATA_FOLDER)
        self.spec_dir = os.path.join(self.build_dir, "spec")
        self.work_dir = os.path.join(self.build_dir, "work")
        for d in [
            self.build_dir,
            self.spec_dir,
            self.work_dir,
            self.pyi_dir,
            self.new_dir,
        ]:
            if os.path.exists(self.work_dir):
                remove_any(self.work_dir)
            if not os.path.exists(d):
                log.debug("Creating directory: %s", d)
                os.mkdir(d)

    # Ensure that a spec file or python script is present
    @staticmethod
    def _check_input_file(pyi_args):
        verified = False
        new_args = []
        app_info = None
        for p in pyi_args:
            if p.endswith(".py"):
                log.debug("Building from python source file: %s", p)
                p_path = os.path.abspath(p)
                log.debug("Source file abs path: %s", p_path)
                app_info = {"type": "script", "name": p_path}
                verified = True

            elif p.endswith(".spec"):
                log.debug("Building from spec file: %s", p)
                app_info = {"type": "spec", "name": p}
                verified = True
            else:
                new_args.append(p)

        if verified is False:
            log.error("Must pass a python script or spec file")
            sys.exit(1)
        return app_info, new_args

    # Take args from PyUpdater then sanatize & combine to be
    # passed to pyinstaller
    def _make_spec(self, temp_name, spec_only=False):
        log.debug("App Info: %s", self.app_info)

        self.pyi_args.append("--name={}".format(temp_name))
        if spec_only is True:
            log.debug("*** User generated spec file ***")
            log.debug("There could be errors")
            self.pyi_args.append("--specpath={}".format(os.getcwd()))
        else:
            # Place spec file in .pyupdater/spec
            self.pyi_args.append("--specpath={}".format(self.spec_dir))

        # Use hooks included in PyUpdater package
        hook_dir = get_hook_dir()
        log.debug("Hook directory: %s", hook_dir)
        self.pyi_args.append("--additional-hooks-dir={}".format(hook_dir))

        if self.args.pyi_log_info is False:
            self.pyi_args.append("--log-level=ERROR")

        self.pyi_args.append(self.app_info["name"])

        log.debug("Make spec cmd: %s", " ".join([c for c in self.pyi_args]))
        success = pyi_makespec(self.pyi_args)
        if success is False:
            log.error("PyInstaller > 3.0 needed for this python installation.")
            sys.exit(1)

    # Actually creates executable from spec file
    def _build(self, spec_file_path, build_args):
        try:
            Version(self.args.app_version)
        except VersionError:
            log.error("Version format incorrect: %s", self.args.app_version)
            log.error(
                """Valid version numbers: 0.10.0, 1.1b, 1.2.1a3

        Visit url for more info:

            http://semver.org/
                      """
            )
            sys.exit(1)
        pyi_build(build_args)

    def _override_dependencies(self, spec_file_path):
        toc = set()
        binaries = set()
        datas = set()
        user_datas = set()
        extensions = set()
        pure_modules = set()
        collected_packages = set()
        CONF["spec"] = spec_file_path
        CONF["specpath"], CONF["specnm"] = os.path.split(CONF["spec"])
        CONF["warnfile"] = os.path.join(self.new_dir, 'warn-%s.txt' % CONF["specnm"])
        CONF['distpath'] = self.new_dir
        CONF["workpath"] = self.work_dir
        CONF['hiddenimports'] = []
        spec_namespace = {
            # Set of global variables that can be used while processing .spec file. Some of them act as configuration
            # options.
            'DISTPATH': self.new_dir,
            'HOMEPATH': None,
            'SPEC': CONF["spec"],
            'specnm': CONF["specnm"],
            'SPECPATH': CONF["specpath"],
            'WARNFILE': CONF["warnfile"],
            'workpath': CONF["workpath"],
            # PyInstaller classes for .spec.
            'TOC': ArgSaver,  # Kept for backward compatibility even though `TOC` class is deprecated.
            'Analysis': ArgSaver,
            'BUNDLE': ArgSaver,
            'COLLECT': ArgSaver,
            'EXE': ArgSaver,
            'MERGE': ArgSaver,
            'PYZ': ArgSaver,
            'Tree': ArgSaver,
            'Splash': ArgSaver,
            # Python modules available for .spec.
            'os': os,
            'pyi_crypto': pyz_crypto,
        }

        try:
            with open(spec_file_path, 'rb') as f:
                # ... then let Python determine the encoding, since ``compile`` accepts byte strings.
                code = compile(f.read(), spec_file_path, 'exec')
        except FileNotFoundError:
            raise SystemExit(f'Spec file "{spec_file_path}" not found!')
        local_scope = {}
        exec(code, spec_namespace, local_scope)
        additional_files = local_scope.get("additional_datas", [])
        analysis_args = local_scope["a"]
        analysis_args.kwargs["excludes"] = []
        analysis = Analysis(*analysis_args.args, **analysis_args.kwargs)
        additional_modules = local_scope.get("additional_modules", [])

        temp_folder = self.new_dir + os.sep + get_system()
        # for file_data in additional_files:
        #     dst_path = file_data[0]
        #     src_path = file_data[1]
        #     file_name = Path(src_path).name
        #     if os.path.isfile(src_path):
        #         datas.update((dst_path, src_path))
        #     elif os.path.isdir(file):
        #         shutil.copytree(file, temp_folder + os.sep + file_name, dirs_exist_ok=True)
        input_datas = [(dest_name, src_name, 'DATA')
                       for dest_name, src_name in format_binaries_and_datas(additional_files, workingdir=self.new_dir)]
        input_datas = sorted(normalize_toc(input_datas))

        # print(analysis.graph.__)

        # for iter_node in analysis.graph.iter_graph(start=analysis.graph._top_script_node):
        #     print(iter_node)

        for entry in input_datas:
            user_datas.add(entry)

        for hidden_module in analysis.hiddenimports:
            for module_name in additional_modules:
                if module_name not in hidden_module:
                    continue
                node = analysis.graph.find_node(hidden_module)
                if node is None:
                    continue
                dependencies = resolve_dependencies(analysis, node)
                binaries.update(dependencies[0])
                datas.update(dependencies[1])
                extensions.update(dependencies[2])
                pure_modules.update(dependencies[3])
                collected_packages.update(dependencies[4])
                #metadata.update(dependencies[5])

        for node in analysis.graph.iter_graph(start=analysis.graph._top_script_node):
            if node is None:
                continue
            for module_name in additional_modules:
                if module_name not in node.identifier:
                    continue
                # node = analysis.graph.find_node(module_name)
                dependencies = resolve_dependencies(analysis, node)
                binaries.update(dependencies[0])
                datas.update(dependencies[1])
                extensions.update(dependencies[2])
                pure_modules.update(dependencies[3])
                collected_packages.update(dependencies[4])
                #metadata.update(dependencies[5])
                # for iter_node in analysis.graph.iter_graph(start=node):
                #     in_dependencies = resolve_dependencies(analysis, iter_node)
                #     binaries.update(in_dependencies[0])
                #     datas.update(in_dependencies[1])
                #     extensions.update(in_dependencies[2])
                #     pure_modules.update(in_dependencies[3])
                #     collected_packages.update(in_dependencies[4])

        # for extension in extensions:
        #     toc.add(add_suffix_to_extension(*extension))
        dist_info = [(dest, source, "DATA") for (dest, source) in
                     format_binaries_and_datas(analysis.graph.metadata_required())]
        datas.update(dist_info)
        #datas.update([(dest, source, "DATA") for (dest, source) in format_binaries_and_datas(metadata)])
        binaries.update(extensions)
        # collected_packages = self.graph.get_collected_packages()
        new_binaries = isolated.call(find_binary_dependencies, binaries, [], collected_packages)
        binaries.update(
            new_binaries
        )
        binaries = postprocess_binaries_toc_pywin32(binaries)
        for binary in binaries:
            # binary_toc = (binary[0], binary[1], "BINARY")
            toc.add(add_suffix_to_extension(*binary))
        for data in datas:
            # data_toc = (data[0], data[1], "DATA")
            toc.add(add_suffix_to_extension(*data))
        for user_data in user_datas:
            data_toc = (user_data[0], user_data[1], "USERDATA")
            toc.add(add_suffix_to_extension(*data_toc))
        # print("FULL DATAS")
        # print(analysis.datas)
        pycs_dir = os.path.join(CONF['workpath'], 'localpycs')
        code_cache = analysis.graph.get_code_objects()
        for pure_module in pure_modules:
            name = pure_module[0]
            src_path = pure_module[1]
            dest_path = name.replace('.', os.sep)
            if src_path in (None, '-'):
                continue
            # Special case: modules have an implied filename to add.
            basename, ext = os.path.splitext(os.path.basename(src_path))
            if basename == '__init__':
                dest_path += os.sep + '__init__'
            # Append the extension for the compiled result. In python 3.5 (PEP-488) .pyo files were replaced by
            # .opt-1.pyc and .opt-2.pyc. However, it seems that for bytecode-only module distribution, we always
            # need to use the .pyc extension.
            dest_path += '.pyc'
            obj_path = compile_pymodule(name, src_path, workpath=pycs_dir, code_cache=code_cache)
            #
            data_pure_module = (dest_path, obj_path, "DATA")
            # data_pure_module = (dest_path, src_path, "DATA")
            toc.add(add_suffix_to_extension(*data_pure_module))

        for toc_element in toc:
            relative_dest = toc_element[0]
            source_path = toc_element[1]
            typecode = toc_element[2]
            if typecode == "USERDATA":
                output_folder = temp_folder
            else:
                output_folder = temp_folder + os.sep + "Lib"
            absolute_dest = output_folder + os.sep + relative_dest
            os.makedirs(os.path.dirname(absolute_dest), exist_ok=True)
            shutil.copyfile(source_path, absolute_dest)

    # Updates name of binary from mac to applications name
    @staticmethod
    def _mac_binary_rename(temp_name, app_name):
        bin_dir = os.path.join(temp_name, "Contents", "MacOS")
        plist = os.path.join(temp_name, "Contents", "Info.plist")
        with ChDir(bin_dir):
            os.rename("mac", app_name)

        # We also have to update to ensure app launches correctly
        with io.open(plist, "r", encoding="utf-8") as f:
            plist_data = f.readlines()

        new_plist_data = []
        for d in plist_data:
            if "mac" in d:
                new_plist_data.append(d.replace("mac", app_name))
            else:
                new_plist_data.append(d)

        with io.open(plist, "w", encoding="utf-8") as f:
            for d in new_plist_data:
                f.write(d)

    # Creates zip on windows and gzip on other platforms
    def _archive(self, temp_name):
        # Now archive the file
        with ChDir(self.new_dir):
            if os.path.exists(temp_name + ".app"):
                log.debug("Got mac .app")
                app_name = temp_name + ".app"
                Builder._mac_binary_rename(app_name, self.app_name)
            elif os.path.exists(temp_name + ".exe"):
                log.debug("Got win .exe")
                app_name = temp_name + ".exe"
            else:
                app_name = temp_name
            version = self.args.app_version
            log.debug("Temp Name: %s", temp_name)
            log.debug("Appname: %s", app_name)
            log.debug("Version: %s", version)

            # Time for some archive creation!
            filename = make_archive(
                self.app_name, app_name, version, self.args.archive_format
            )
            log.debug("Archive name: %s", filename)
            if self.args.keep is False:
                if os.path.exists(temp_name):
                    log.debug("Removing: %s", temp_name)
                    remove_any(temp_name)
                if os.path.exists(app_name):
                    log.debug("Removing: %s", temp_name)
                    remove_any(app_name)
        log.debug("%s has been placed in your new folder\n", filename)


class ExternalLib(object):
    def __init__(self, name, version):
        self.name = name
        self.version = version

    def archive(self):
        filename = create_asset_archive(self.name, self.version)
        log.debug("Created archive for %s: %s", self.name, filename)


def is_standard_module(_node):
    module_name = _node.identifier
    package_name = module_name.split(".")[0]
    return package_name in STDLIB_MODULES


def resolve_dependencies(analysis, _node, top_level=False):
    binaries = set()
    datas = set()
    extensions = set()
    pure_modules = set()
    collected_packages = set()

    # print(_node)

    regex_str = '(' + '|'.join(PY3_BASE_MODULES) + r')(\.|$)'
    module_filter = re.compile(regex_str)
    if module_filter.match(_node.identifier):
        return binaries, datas, extensions, pure_modules, collected_packages

    # if "Qt6" in _node.identifier:
    #     print("PACKAGE NAME", _node)
    #     if _node.identifier in analysis.graph._additional_files_cache:
    #         print(analysis.graph._additional_files_cache.binaries(_node.identifier))
    #     print(analysis.graph._node_to_toc(_node, BINARY_MODULE_TYPES))

    if analysis.graph.is_a_builtin(_node):
        return binaries, datas, extensions, pure_modules, collected_packages
    if not type(_node).__name__ in ["Extension", "Package", "SourceModule"] and not top_level:
        return binaries, datas, extensions, pure_modules, collected_packages
    if is_standard_module(_node):
        return binaries, datas, extensions, pure_modules, collected_packages

    if type(_node).__name__ == "Package":
        collected_packages.add(_node.identifier)

    # print(_node.graphident)
    # print(analysis.graph._node_to_toc(_node, PURE_PYTHON_MODULE_TYPES))

    name = _node.identifier
    if name in analysis.graph._additional_files_cache:  # Correct Data
        temp_binaries = analysis.graph._additional_files_cache.binaries(name)
        for binary in temp_binaries:
            binaries.add((binary[0], binary[1], "BINARY"))
        # binaries.update(temp_binaries)
        temp_datas = analysis.graph._additional_files_cache.datas(name)
        for data in temp_datas:
            datas.add((data[0], data[1], "DATA"))
        # datas.update(temp_datas)
    temp_extensions = analysis.graph._node_to_toc(_node, BINARY_MODULE_TYPES)
    if temp_extensions:
        extensions.add(temp_extensions)
    temp_pure_modules = analysis.graph._node_to_toc(_node, PURE_PYTHON_MODULE_TYPES)
    if temp_pure_modules:
        pure_modules.add(temp_pure_modules)
    return binaries, datas, extensions, pure_modules, collected_packages
