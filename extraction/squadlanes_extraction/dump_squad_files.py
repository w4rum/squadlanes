import os
import subprocess
import sys
from glob import glob
from pprint import pprint

from squadlanes_extraction import config
from pwn import log, logging
from pwnlib.log import Progress
from pwnlib.context import context

VANILLA_SUBDIR = "/SquadGame/Content/Paks"
CAF_SUBDIR = "/SquadGame/Plugins/Mods/CanadianArmedForces/Content/Paks/WindowsNoEditor"


def _unpack_pak_with_filter(pak_path: str, filter: str) -> None:
    command = [
        f"wine",
        config.UNREAL_PAK_PATH,
        f"Z:/{pak_path}",
        f"-cryptokeys=Z:/{os.path.abspath(config.CRYPTO_JSON_PATH)}",
        f"-Extract",
        f"Z:/{os.path.abspath(config.UNPACKED_ASSETS_DIR)}",
        f"-Filter={filter}",
    ]

    if context.log_level <= logging.DEBUG:
        pprint(command)
        sys.stdout.flush()
        stdout = sys.stdout
        stderr = sys.stderr
    else:
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL

    subprocess.call(command, stdout=stdout, stderr=stderr)


def _unpack_relevant_files_in_dir(paks_dir_path: str, progress: Progress) -> None:
    for name in os.listdir(paks_dir_path):
        progress.status(name)

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
        _unpack_pak_with_filter(path, "*.umap")

        # Need to get uexp, ubulk and uassets as well to correctly extract minimaps
        # TODO: improve filter to only extract minimaps, not all files
        _unpack_pak_with_filter(path, "*.uexp")
        _unpack_pak_with_filter(path, "*.ubulk")
        _unpack_pak_with_filter(path, "*.uasset")


def unpack():
    os.makedirs(config.UNPACKED_ASSETS_DIR, exist_ok=True)

    with log.progress("-- Unpacking Vanilla Assets") as progress:
        _unpack_relevant_files_in_dir(config.SQUAD_GAME_DIR + VANILLA_SUBDIR, progress)

    with log.progress("-- Unpacking CAF Assets") as progress:
        _unpack_relevant_files_in_dir(config.SQUAD_GAME_DIR + CAF_SUBDIR, progress)

    # some assets are extracted into a different directories
    # e.g., "./Content/" vs. "./SquadGame/Content/"
    # (not sure why this is inconsistent)
    with log.progress("-- Merging directories"):
        merge_paths = [
            ("SquadGame", "."),
            ("Plugins/Mods/CanadianArmedForces/", "."),
            ("Content", "."),
        ]
        for src, dst in merge_paths:
            subprocess.call(
                [
                    "cp",
                    "--recursive",
                    "--link",  # don't copy, hard-link instead
                    *glob(f"{config.UNPACKED_ASSETS_DIR}/{src}/*"),
                    f"{config.UNPACKED_ASSETS_DIR}/{dst}",
                ],
            )
