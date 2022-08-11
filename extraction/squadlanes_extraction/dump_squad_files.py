import asyncio
import os
import shlex
import subprocess
import sys
from glob import glob
from pprint import pprint

from pwn import log, logging
from pwnlib.context import context

from squadlanes_extraction import config

VANILLA_SUBDIR = "/SquadGame/Content/Paks"

parallel_limit = asyncio.Semaphore(config.MAXIMUM_PARALLEL_UNPACKS)


async def _unpack_pak_with_filter(pak_path: str, filters: list[str], name: str) -> None:
    async with parallel_limit:
        with log.progress(f"Unpacking: {name}"):
            for flt in filters:
                command = [
                    f"wine",
                    config.UNREAL_PAK_PATH,
                    f"Z:/{pak_path}",
                    f"-cryptokeys=Z:/{os.path.abspath(config.CRYPTO_JSON_PATH)}",
                    f"-Extract",
                    f"Z:/{os.path.abspath(config.UNPACKED_ASSETS_DIR)}",
                    f"-Filter={flt}",
                ]

                if context.log_level <= logging.DEBUG:
                    pprint(command)
                    sys.stdout.flush()
                    stdout = asyncio.subprocess.PIPE
                    stderr = asyncio.subprocess.PIPE
                else:
                    stdout = asyncio.subprocess.DEVNULL
                    stderr = asyncio.subprocess.DEVNULL

                process = await asyncio.subprocess.create_subprocess_shell(
                    shlex.join(command), stdout=stdout, stderr=stderr
                )
                await process.wait()


async def _unpack_relevant_files_in_dir(paks_dir_path: str) -> None:
    unpack_runs = []

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

        unpack_runs.append(
            _unpack_pak_with_filter(
                path, ["*.umap", "*.uexp", "*.ubulk", "*.uasset"], name
            )
        )

    await asyncio.gather(*unpack_runs)


def unpack():
    os.makedirs(config.UNPACKED_ASSETS_DIR, exist_ok=True)

    asyncio.run(_unpack_relevant_files_in_dir(config.SQUAD_GAME_DIR + VANILLA_SUBDIR))

    # some assets are extracted into a different directories
    # e.g., "./Content/" vs. "./SquadGame/Content/"
    # (not sure why this is inconsistent)
    # BlackCoast is also an "expansion" and thus in a different directory
    with log.progress("Merging directories"):
        merge_paths = [
            ("SquadGame", "."),
            ("Content", "."),
            ("Plugins/Expansions/BlackCoast/Content/Maps", "Maps/BlackCoast"),
        ]
        for src, dst in merge_paths:
            out_dir = f"{config.UNPACKED_ASSETS_DIR}/{dst}"
            os.makedirs(out_dir, exist_ok=True)
            subprocess.call(
                [
                    "cp",
                    "--recursive",
                    "--link",  # don't copy, hard-link instead
                    *glob(f"{config.UNPACKED_ASSETS_DIR}/{src}/*"),
                    out_dir,
                ],
            )
