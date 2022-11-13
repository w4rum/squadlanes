from squadlanes_extraction import (
    dump_squad_files,
    extract_map_info,
    generate_map_tiles,
)


def unpack():
    print(
        "Unpacking Unreal assets. "
        "This will take a few minutes (and lots of disk space!)."
    )

    dump_squad_files.unpack()

    print("Unpacking finished. You can run the extract task now.")


def extract():
    print("Extracting layer info. This will take a few minutes.")

    extract_map_info.extract()

    print(
        "Extraction finished. "
        "You can generate map tiles now. "
        "The RAAS data has been saved as raas-data-auto.yaml. "
        "Make any changes that you want to make to it and then copy it to "
        "../src/assets/raas-data.yaml"
    )


def tiles():
    print(
        "Generating map tiles. "
        "This will take a few minutes and you won't see any progress for a while."
    )

    generate_map_tiles.tiles()

    print(
        "Map tiles generated. "
        "You now have all the assets necessary to run the website."
    )
