import glob
import json
import os
import shutil
import subprocess
from pathlib import Path, PurePath
from pprint import pprint as pp
from collections import namedtuple
DEFAULT_PAT_GENERATED_PAT = "."

PatFileInfo = namedtuple('PatFileInfo',['path', 'skipped', 'total'])

class FlairLibEnv:
    NAME = ''
    SRC_PATH = ''
    VERSION = ''
    COMMENT = ''
    COMPILER = ''
    RESULT_DIR = ''
    SIG_FILE_NAME = ''
    __instance = None

    def __init__(self, lib_env: tuple, json_config={}):
        self.json_config = json_config

        self.NAME, self.VERSION, self.SRC_PATH, self.COMPILER, self.COMMENT, self.RESULT_DIR = lib_env
        if len(self.RESULT_DIR)==0:
            self.RESULT_DIR = Path(self.result_dir).joinpath(Path('sigmake_temp')).absolute().as_posix()
        self.create_result_dir()
        self.SIG_FILE_NAME = self.get_sig_filename()
        FlairLibEnv.__instance = self

    def create_result_dir(self):
        temp_sig_dir = Path(self.RESULT_DIR)
        if not temp_sig_dir.exists():
            print(f"create {temp_sig_dir.as_posix()}")
            temp_sig_dir.mkdir(parents=True)


    @staticmethod
    def instance():
        return FlairLibEnv.__instance

    @property
    def sig_info(self):
        return (self.NAME, self.VERSION, self.SIG_FILE_NAME, self.COMMENT)

    def flirt_info_add(self, info: dict):
        self.json_config['flirt'] = self.generate_flirt_info(info)

    def generate_flirt_info(self, info: tuple):
        return {
            'pat': "+".join(pats),
            'cmdline': cmdline,
            'obj': "+".join(pats),
        }

    def get_sig_filename(self):
        sig_file = f"{self.NAME}_{self.VERSION}_{self.COMPILER}.{FlairWin.SIG_FILE}"
        return sig_file

    @property
    def result_dir(self):
        return self.RESULT_DIR


class FlairWin:
    FLAIR_PATH = "c:/tools/helpers/bin/"

    PATTERN_FILE = 'pat'
    OBJ_FILE = 'obj'
    SIG_FILE = 'sig'
    SIG_PATTERN = '*.' + SIG_FILE

    # WIN_TOOLS
    PCF_BIN = 'pcf.exe'
    SIGMAKE_BIN = 'sigmake.exe'

    def __init__(self, flair_tools_path=None):
        self.lib_flair_dir = None
        if flair_tools_path is not None:
            FlairWin.FLAIR_PATH = flair_tools_path

    def init_library_env(self, LIB_FLAIR_DIR) -> Path:
        self.lib_flair_dir = LIB_FLAIR_DIR
        Path(LIB_FLAIR_DIR).mkdir(parents=True, exist_ok=True)
        return self.env_path

    @property
    def env(self) -> str:
        return self.lib_flair_dir

    @property
    def env_path(self) -> Path:
        return Path(self.lib_flair_dir)

    @property
    def env_pure(self) -> PurePath:
        return PurePath(self.lib_flair_dir)

    @staticmethod
    def pcf_file():
        return f"{FlairWin.FLAIR_PATH}{FlairWin.PCF_BIN}"

    @staticmethod
    def sigmake_file():
        return f"{FlairWin.FLAIR_PATH}{FlairWin.SIGMAKE_BIN}"


class FileStorage:
    def __init__(self, type, files: list):
        self.type = type
        self._data = {
            'count': len(files),
            'size': map(lambda n: Path(n).stat().st_size, files),
            'files': files
        }


class FlairTool:
    __storage = {}
    __counter = {}
    __files = {
        FlairWin.OBJ_FILE: {
            'count': 0,
            'size': 0,
            'files': []
        },
        FlairWin.PATTERN_FILE: []
    }


    __patternFiles = {}

    __path = ''

    @staticmethod
    def _collect_files(path, pattern='**/*', ext='.txt', recursive=True):
        pattern = f"{path}/{pattern}{ext}"
        return glob.glob(pattern, recursive=recursive)

    @staticmethod
    def set_path(path):
        FlairTool.__path = path
        return FlairTool

    @staticmethod
    def get_path():
        return FlairTool.__path

    @staticmethod
    def collect_pat_files() -> dict:
        p = FlairTool.get_path()
        pat_file_dict = {PurePath(file): PurePath(file).as_posix() for file in
                         FlairTool._collect_files(p, ext=FlairWin.PATTERN_FILE)}
        FlairTool.__files[FlairWin.PATTERN_FILE] = pat_file_dict
        return pat_file_dict

    @staticmethod
    def get_collected_files():
        return FlairTool.__files

    @staticmethod
    def collect_obj_files() -> list:
        p = FlairTool.get_path()
        file_list = FlairTool._collect_files(p, ext=FlairWin.OBJ_FILE)
        FlairTool.__files[FlairWin.OBJ_FILE] = file_list
        return file_list

    @staticmethod
    def get_storage() -> dict:
        return FlairTool.__storage

    @staticmethod
    def store(pair: tuple):
        name, content = pair
        st = FlairTool.get_storage()
        try:
            current = st[name]
        except KeyError:
            st[name] = content

    @staticmethod
    def sigmake_process(pat_names, output_path=None) -> subprocess.CompletedProcess:
        lib_name, ver, sig_file, comment = FlairLibEnv.instance().sig_info
        if output_path is None:
            # wrong
            output_path = Path.joinpath(Path(os.curdir), Path(sig_file)).as_posix()  # f"d:/{sig_file}"

        sigmake_params = ['-X','-d','-v',f"-n{lib_name}",f"{pat_names}",output_path]

        proc = [FlairWin.sigmake_file()] + sigmake_params
        sigmake_cmd_line = " ".join(proc)
        print(f"Sigmake command:\n {sigmake_cmd_line}")
        try:
            r = subprocess.run(proc, shell=True, check=True,capture_output=True)
            return r
        except subprocess.CalledProcessError as cpe:
            pp("Sigmake returned nonzero")
            if str(cpe.output).find("Resolving collisions")>=0:
                print("You have to resolve collisions")
                files = (output_path+'.err',output_path+ '.exc')
                print(f"see {files}")

            pp(cpe)

        return None



    @staticmethod
    def pcr_proc_file(lib_file) -> PatFileInfo:
        file_info = None
        pcf_tool = [FlairWin.pcf_file(), "-p64", lib_file]
        r = subprocess.run(pcf_tool, shell=True, check=True, capture_output=True, text=True)
        print(r, pcf_tool)

        values = str(r.stderr).split(" ")
        print('pcf', values)
        if (len(values) == 5):
            file, null1, skipped_count, null2, total_count = values
            path = PurePath(file[:-1])
            file_info = PatFileInfo(path, int(skipped_count[:-1]), int(total_count))
            print(f"Processed lib: {path.name}, {int(total_count)}, skipped: {skipped_count[:-1]}")
            return file_info
        else:
            pp(f"Error? {r.stderr}")
            return None

    @staticmethod
    def get_pattern_files():
        return FlairTool.__patternFiles

    @staticmethod
    def sigmake(pat_files=None):

        pure_path_list: list[PurePath] = list(FlairTool.get_pattern_files().values())
        folder = pure_path_list[0].parent.as_posix()
        os.chdir(folder)
        pat_file_names = "+".join([f"{f.stem}.{FlairWin.PATTERN_FILE}" for f in pure_path_list])
        p = FlairTool.sigmake_process(pat_file_names)
        pp(p)

    @staticmethod
    def create_pat_files(obj_files: list):
        pats = FlairTool.get_pattern_files()

        for lib in obj_files:
            pat_info = FlairTool.pcr_proc_file(lib)
            if pat_info is not None:
                path, skipped, total = pat_info
                pats[path] = (skipped, total)

        return FlairTool.collect_pat_files()

    @staticmethod
    def move_all_pat(pattern_files,destination_dir:str):
        i = 0
        #pattern_files = FlairTool.collect_pat_files()
        FlairTool.__patternFiles.clear()

        for path, file in pattern_files.items():
            path: PurePath
            abs_path = Path(path).resolve().as_posix()
            FlairTool.__patternFiles[i] = Path(destination_dir + "/" + Path(path).name)


            try:
                r = shutil.copy(abs_path, destination_dir)
                i += 1
                print(f"i:{i}, {r}")
            except shutil.Error as e:
                print("Error ", e)


class Config:
    __instance = None

    def __init__(self, library_name, path_to_build, version=None, compiler=None):
        self.library_name = library_name
        self.path_to_build = path_to_build

    @staticmethod
    def from_config(settings_file_name) -> FlairLibEnv:
        f = open(settings_file_name, 'r')
        conf: dict = json.load(f)
        f.close()
        return FlairLibEnv(conf.values(), conf)


flair_win = FlairWin()

# create flair tool with config
tools = FlairTool.set_path(Config.from_config("sig-config.json").SRC_PATH)
flair_app:FlairLibEnv = FlairLibEnv.instance()

# get object files
obj_files = tools.collect_obj_files()
pat_files = tools.create_pat_files(obj_files)
tools.move_all_pat(pat_files,flair_app.RESULT_DIR)
tools.sigmake()
