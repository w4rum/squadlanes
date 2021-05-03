import os
import subprocess
import sys
from concurrent.futures.thread import ThreadPoolExecutor
from pprint import pprint

from pwn import logging, log
from pwnlib.context import context

from squadlanes_extraction import config


def tiles():
    os.makedirs(config.TILE_MAP_DIR, exist_ok=True)

    if not os.path.isdir(config.FULLSIZE_MAP_DIR):
        log.error(
            f"Configured FULLSIZE_MAP_DIR does not exist.\n"
            f"Make sure you run the extract task first."
        )

    with ThreadPoolExecutor() as executor:
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

            if context.log_level <= logging.DEBUG:
                pprint(command)
                sys.stdout.flush()
                stdout = sys.stdout
                stderr = sys.stderr
            else:
                stdout = subprocess.DEVNULL
                stderr = subprocess.DEVNULL

            executor.submit(extract_minimap, name, command, stdout, stderr)


def extract_minimap(name: str, command: str, stdout, stderr):
    with log.progress(f"-- Generating tiles for {name}"):
        subprocess.call(command, stdout=stdout, stderr=stderr)
