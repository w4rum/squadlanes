from pwn import log, context

from squadlanes_extraction import (
    config,
    dump_squad_files,
    extract_map_info,
    generate_map_tiles,
)

context.log_level = config.LOG_LEVEL


def unpack():
    with log.progress("Unpacking game files"):
        dump_squad_files.unpack()

    log.success("Unpacking finished. You can run the extract task now.")


def extract():
    with log.progress("Extracting RAAS data and full-size maps"):
        extract_map_info.extract()

    log.success(
        "Extraction finished. "
        "You can generate map tiles now. "
        "The RAAS data has been saved as raas-data-auto.yaml. "
        "Make any changes that you want to make to it and then copy it to "
        "../src/assets/raas-data.yaml"
    )


def tiles():
    with log.progress("Generating map tiles"):
        generate_map_tiles.tiles()

    log.success(
        "Map tiles generated. "
        "You now have all the assets necessary to run the website."
    )
