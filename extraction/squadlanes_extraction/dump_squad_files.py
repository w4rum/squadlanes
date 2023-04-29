import asyncio
import os
import shlex
import sys
from pprint import pprint

from tqdm.asyncio import tqdm

from squadlanes_extraction import config

parallel_limit = asyncio.Semaphore(config.MAXIMUM_PARALLEL_TASKS)

async def _unpack_pak_with_filter(
    pak_bundle_name: str,
    pak_path: str,
    filters: list[str],
) -> None:
    async with parallel_limit:
        for flt in filters:
            if sys.platform == 'win32':
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
                destination_dir = os.path.join(
                    os.path.abspath(config.UNPACKED_ASSETS_DIR), pak_bundle_name
                )

                command = [
                    os.path.abspath(config.UNREAL_PAK_PATH).replace('\\', '/'),
                    f"{pak_path}",
                    "-cryptokeys=" + os.path.abspath(config.CRYPTO_JSON_PATH).replace('\\', '/'),
                    f"-Extract",
                    "" + destination_dir.replace('\\', '/'),
                    f"-Filter={flt}",
                ]

                process = await asyncio.subprocess.create_subprocess_shell(
                    shlex.join(command).replace("'", '"')
                )
                await process.wait()
            else:
                destination_dir = os.path.join(
                    "Z:/", os.path.abspath(config.UNPACKED_ASSETS_DIR), pak_bundle_name
                )

                command = [
                    f"wine",
                    config.UNREAL_PAK_PATH,
                    f"Z:/{pak_path}",
                    f"-cryptokeys=Z:/{os.path.abspath(config.CRYPTO_JSON_PATH)}",
                    f"-Extract",
                    destination_dir,
                    f"-Filter={flt}",
                ]

                if config.LOG_LEVEL == "DEBUG":
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


async def _unpack_relevant_files_in_dir(pak_bundles: dict[str, str]) -> None:
    unpack_runs = []

    for pak_bundle_name, pak_bundle_path in pak_bundles.items():
        for pak_name in os.listdir(pak_bundle_path):
            path = f"{pak_bundle_path}/{pak_name}"

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
                    pak_bundle_name,
                    path,
                    ["*.umap", "*.uexp", "*.ubulk", "*.uasset"],
                )
            )

    await tqdm.gather(*unpack_runs)


def unpack():
    os.makedirs(config.UNPACKED_ASSETS_DIR, exist_ok=True)

    # unpack vanilla assets
    pak_bundles = {
        "Vanilla": config.SQUAD_GAME_DIR,
    }
    # unpack mod assets (paths are assumed to point to the pak dir)
    for mod_name, mod_pak_dir in config.MODS.items():
        pak_bundles[mod_name] = mod_pak_dir

    asyncio.run(_unpack_relevant_files_in_dir(pak_bundles))
