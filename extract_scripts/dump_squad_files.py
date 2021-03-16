import os
import subprocess
import sys
from pprint import pprint

UNREAL_PAK_PATH = "/home/tim/Downloads/UnrealPakTool/UnrealPak.exe"
CRYPTO_JSON_PATH = "/home/tim/Downloads/UnrealPakTool/Crypto.json"

SQUAD_GAME_DIR_PATH = "/mnt/win/Program Files (x86)/Steam/steamapps/common/Squad"
EXTRACT_DIR_PATH = "/mnt/win/Users/Tim/Desktop/squad-dump"

VANILLA_SUBDIR = "/SquadGame/Content/Paks"
CAF_SUBDIR = "/SquadGame/Plugins/Mods/CanadianArmedForces/Content/Paks/WindowsNoEditor"

VERBOSITY = 1


def extract(pak_path: str, filter: str) -> None:
    command = [
        f"wine",
        UNREAL_PAK_PATH,
        f"Z:/{pak_path}",
        f"-cryptokeys=Z:/{CRYPTO_JSON_PATH}",
        f"-Extract",
        f"Z:/{EXTRACT_DIR_PATH}",
        f"-Filter={filter}",
    ]

    if VERBOSITY >= 1:
        pprint(command)
        sys.stdout.flush()

    if VERBOSITY >= 2:
        stdout = sys.stdout
        stderr = sys.stderr
    else:
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL

    subprocess.call(command, stdout=stdout, stderr=stderr)


def unpack_all_paks(paks_dir_path: str) -> None:
    for name in os.listdir(paks_dir_path):

        path = f"{paks_dir_path}/{name}"

        # ignore dirs
        if not os.path.isfile(path):
            continue
        # ignore files that are not PAKs
        if not path.endswith(".pak"):
            continue
        # ignore truncated files
        if os.stat(path).st_size == 0:
            continue

        # extract layer info
        extract(path, "*.umap")

        # Need to get uexp, ubulk and uassets as well to correctly extract minimaps
        # TODO: improve filter to only extract minimaps, not all files
        extract(path, "*.uexp")
        extract(path, "*.ubulk")
        extract(path, "*.uasset")


os.makedirs(EXTRACT_DIR_PATH, exist_ok=True)

print("### Extracting Vanilla", flush=True)
unpack_all_paks(SQUAD_GAME_DIR_PATH + VANILLA_SUBDIR)
print("### Extracting CAF", flush=True)
unpack_all_paks(SQUAD_GAME_DIR_PATH + CAF_SUBDIR)

# some CAF maps are extracted into a different directory
# (not sure why this is inconsistent)
print("### Merging CAF into Vanilla")
subprocess.call(
    [
        "cp",
        "--recursive",
        "--link",  # don't copy, hard-link instead
        f"{EXTRACT_DIR_PATH}/Plugins/Mods/CanadianArmedForces/Content/",
        EXTRACT_DIR_PATH,
    ]
)
