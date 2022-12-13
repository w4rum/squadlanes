import concurrent.futures
import os
import subprocess
import sys
from concurrent.futures.thread import ThreadPoolExecutor
from pprint import pprint

from tqdm import tqdm

from squadlanes_extraction import config


def tiles():
    os.makedirs(config.TILE_MAP_DIR, exist_ok=True)

    if not os.path.isdir(config.FULLSIZE_MAP_DIR):
        print(
            f"Configured FULLSIZE_MAP_DIR does not exist.\n"
            f"Make sure you run the extract task first."
        )
        return

    # limit workers. each worker is going to spawn 16 processes anyway
    # todo: use MAX_PARALLEL_TASKS / 16 * 2
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = []

        for name in os.listdir(config.FULLSIZE_MAP_DIR):
            # ignore non-tga files
            if not name.endswith(".tga"):
                continue

            # remove extension
            name, _, _ = name.rpartition(".tga")

            # We need to create a new user and group inside the Docker container,
            # otherwise the generated files will be owned by root on our host system,
            # which is annoying.
            # generate-map-tiles.sh takes care of that
            command = [
                f"docker",
                f"run",
                f"--mount",
                f"type=bind,source={os.path.abspath(config.FULLSIZE_MAP_DIR)},target=/mnt/map-fullsize",
                f"--mount",
                f"type=bind,source={os.path.abspath(config.TILE_MAP_DIR)},target=/mnt/map-tiles",
                f"--mount",
                f"type=bind,source={os.getcwd()},target=/mnt/cwd",
                f"osgeo/gdal",
                f"sh",
                f"/mnt/cwd/generate-map-tiles.sh",
                f"{os.getuid()}",
                f"{os.getgid()}",
                f"{name}",
            ]

            if config.LOG_LEVEL == "DEBUG":
                pprint(command)
                sys.stdout.flush()
                stdout = sys.stdout
                stderr = sys.stderr
            else:
                stdout = subprocess.DEVNULL
                stderr = subprocess.DEVNULL

            futures.append(executor.submit(extract_minimap, command, stdout, stderr))

        with tqdm(total=len(futures)) as pbar:
            for _ in concurrent.futures.as_completed(futures):
                pbar.update(1)


def extract_minimap(command: str, stdout, stderr):
    subprocess.call(command, stdout=stdout, stderr=stderr)
