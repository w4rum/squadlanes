import asyncio
import math
import os
import re
import struct
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, List, Union, Set

import yaml
from pwn import log, context, logging, sys
from pwnlib.log import Progress, Logger

from squadlanes_extraction import config

SINGLE_LANE_NAME = "Center"

GAME_MODES = ["RAAS", "Invasion"]


def add_tuples(*tuples: Tuple):
    s = []
    for elements in zip(*tuples):
        cur_sum = 0
        for e in elements:
            cur_sum += e
        s.append(cur_sum)
    return tuple(s)


def index_dict_to_list(list_dict: dict):
    """
    Takes a list in dict-form (indices = keys) and transform it into a proper list, obeying the
    included indices.

    Example:
    { "0": "A", "1": "B", "2": "C" } => ["A", "B", "C"]
    """
    highest_index = -1
    for key in list_dict.keys():
        key = int(key)
        if highest_index < key:
            highest_index = key

    l = []
    for i in range(highest_index + 1):
        l.append(list_dict[i])
    return l


def to_cluster(cluster_name: str, docs: List[dict]):
    cluster_root_dict = None
    for obj_dict in docs:
        if sdk_name(obj_dict) == cluster_name:
            cluster_root_dict = access_one(obj_dict)
            break
    assert cluster_root_dict is not None

    # TODO: sometimes sdk names are reused
    # - Skorpo RAAS v2, North has SteinslettaFootHills in 1 and 2 but display names and pos are different
    # - Skorpo RAAS v3, South has Beltedals in 3 and 4, different pos
    if cluster_root_dict["ClassName"] in [
        "BP_CaptureZoneMain_C",
        "BP_CaptureZone_C",
        "BP_CaptureZoneInvasion_C",
    ]:
        return [
            to_capture_point(
                cluster_root_dict,
                cluster_root_dict["ClassName"],
                cp_sdk_name({cluster_name: ""}),
            )
        ]
    else:
        assert cluster_root_dict["ClassName"] == "BP_CaptureZoneCluster_C"

    cluster = []
    # iterate over all CPs and only take CPs that have this cluster as parent
    for obj_dict in docs:
        obj = access_one(obj_dict)
        if obj["ClassName"] not in ["BP_CaptureZone_C", "BP_CaptureZoneInvasion_C"]:
            continue
        direct_parent_name = access_one(
            access_one(obj["DefaultSceneRoot"])["AttachParent"]
        )["OuterName"]
        if direct_parent_name != cluster_name:
            continue
        cluster.append(to_capture_point(obj, obj["ClassName"], cp_sdk_name(obj_dict)))

    # sort capture points by SDK name to avoid large git diffs when UEViewer changes arbitrary order
    cluster.sort(key=lambda cp: cp["sdk_name"])

    return cluster


def cp_sdk_name(cp_dict: dict):
    sdk_name = None
    for key in cp_dict.keys():
        if key != "ClassName":
            sdk_name = key
            break
    assert sdk_name is not None
    _, _, sdk_name = sdk_name.rpartition(".")
    # TODO: fix TractorCo-op
    _, _, sdk_name = sdk_name.rpartition("-")
    return sdk_name


def sdk_name(obj_dict: dict):
    for key in obj_dict.keys():
        if key != "ClassName":
            return key
    assert False


def to_capture_point(cp_dict: dict, class_name: str, sdk_name: str):
    cap_zone_name = "SQCaptureZone"
    if class_name == "BP_CaptureZoneInvasion_C":
        cap_zone_name = "SQCaptureZoneInvasion"

    display_name = access_one(cp_dict[cap_zone_name])["FlagName"]
    x, y = absolute_location(cp_dict["DefaultSceneRoot"])
    # TODO: capture range geometrics
    if len(display_name) == 0:
        # try to generate a nice display name from the SDK name
        # stolen from https://stackoverflow.com/a/37697078
        display_name = " ".join(
            re.sub(
                "([A-Z][a-z]+)", r" \1", re.sub("([A-Z]+)", r" \1", sdk_name)
            ).split()
        )
    return {"sdk_name": sdk_name, "display_name": display_name, "x": x, "y": y}


def absolute_location(
    scene_root: Union[dict, str],
    offset: tuple[float, float] = (0, 0),
):
    # if we've traversed back to the root, simply return the offset
    if scene_root == "None":
        return offset

    # remove an unnecessary layer of nesting
    scene_root = access_one(scene_root)

    # 1. rotate the current offset by this object's rotation, if it has a rotation
    if "RelativeRotation" in scene_root:
        rel_rot = scene_root["RelativeRotation"]

        # note: z axis, roll, and pitch should be zero for clusters etc. and are ignored

        # for some reason, UEViewer treats the rotation as ints, when they're actually floats
        # see https://docs.unrealengine.com/4.27/en-US/API/Runtime/Core/Math/FRotator/
        yaw_degrees: float = struct.unpack("<f", struct.pack("<i", rel_rot["Yaw"]))[0]

        rotated_offset = rotate(offset, yaw_degrees)
    else:
        rotated_offset = offset

    # 2. translate the current offset by this object's translation
    rel_loc = scene_root["RelativeLocation"]
    rel_loc = (rel_loc["X"], rel_loc["Y"])

    rel_loc_with_offset = add_tuples(rotated_offset, rel_loc)

    # 3. if the location is relative, traverse the tree upwards towards the root
    if not scene_root.get("bAbsoluteLocation", False):
        parent = scene_root["AttachParent"]
        abs_loc = absolute_location(parent, rel_loc_with_offset)
    else:
        abs_loc = rel_loc_with_offset

    return abs_loc


def rotate(loc: tuple[float, float], yaw_degrees: float) -> tuple[float, float]:
    yaw_radians = math.radians(yaw_degrees)

    x, y = loc

    rotated_x = x * math.cos(yaw_radians) - y * math.sin(yaw_radians)
    rotated_y = x * math.sin(yaw_radians) + y * math.cos(yaw_radians)

    return rotated_x, rotated_y


def get_lane_graph_and_clusters(docs: List[dict]):
    # get lane graph and clusters
    for obj in docs:
        obj = access_one(obj)
        if obj["ClassName"] == "SQRAASLaneInitializer_C":
            lane_graph, clusters = multi_lane_graph(obj, docs)
            break
        if obj["ClassName"] == "SQGraphRAASInitializerComponent":
            lane_graph, clusters = single_lane_graph(obj, docs)
            break
    else:
        assert False, "no RAAS initializer found"

    # identify main clusters
    mains = []
    for obj in docs:
        if access_one(obj)["ClassName"] != "BP_CaptureZoneMain_C":
            continue
        mains.append(cp_sdk_name(obj))
    assert len(mains) == 2, f"found {len(mains)} main bases"

    mains.sort()

    return lane_graph, clusters, mains


def multi_lane_graph(initializer_dict: dict, docs: List[dict]):
    lane_graph = {}
    cluster_names = set()
    for lane in index_dict_to_list(initializer_dict["AASLanes"]):
        lane: dict
        # TODO: fix CENTRAL
        # TODO: Lashkar CAF RAAS v1 has single lane '01'
        lane_name = lane["LaneName"].title()
        link_list, pretty_link_list = get_link_list(lane["AASLaneLinks"])
        cluster_names |= get_cluster_names(link_list)
        lane_graph[lane_name] = pretty_link_list
    clusters = get_cluster_list(cluster_names, docs)
    return lane_graph, clusters


def single_lane_graph(initializer_dict: dict, docs: List[dict]):
    link_list, pretty_link_list = get_link_list(initializer_dict["DesignOutgoingLinks"])
    clusters = get_cluster_list(get_cluster_names(link_list), docs)
    lane_graph = {
        SINGLE_LANE_NAME: pretty_link_list,
    }
    return lane_graph, clusters


def prettify_cluster_name(cluster_name):
    pretty = cluster_name.rpartition(".")[2]
    assert pretty != ""
    return pretty


def get_link_list(
    raw_link_dict: dict,
):
    # raw_link_dict is a dict in the form: index -> object
    # transform that to a proper list, obeying the included indices
    raw_link_list = index_dict_to_list(raw_link_dict)

    # throw away all of the object info
    # the only thing we care about are the SDK names of the node
    links = []
    for raw_link in raw_link_list:
        # since 2.12, some links are broken, containing only one element
        # this is the same in the SDK, so I assume OWI fucked this up and this isn't just an
        # incorrect extraction
        # I also assume that the actual game silently ignores these links
        if raw_link["NodeA"] == "None" or raw_link["NodeB"] == "None":
            continue

        links.append((sdk_name(raw_link["NodeA"]), sdk_name(raw_link["NodeB"])))

    pretty_link_list = list(
        map(
            lambda l: {
                "a": prettify_cluster_name(l[0]),
                "b": prettify_cluster_name(l[1]),
            },
            links,
        )
    )
    return links, pretty_link_list


def get_cluster_names(link_list: List[Tuple[str, str]]):
    # flatten links list and remove duplicates
    cluster_names = set()
    for a, b in link_list:
        cluster_names.add(a)
        cluster_names.add(b)
    return cluster_names


def get_cluster_list(cluster_names: Set[str], docs: List[dict]):
    clusters = {}
    for name in cluster_names:
        pretty_name = prettify_cluster_name(name)
        clusters[pretty_name] = to_cluster(name, docs)
    return clusters


async def extract_layer(
    layer: str,
    game_mode: str,
    pretty_map_name: str,
    gameplay_layer_dir: str,
    map_dir: str,
) -> dict:
    # extract map information from umap with umodel
    yaml_filename = f"{config.LAYER_DUMP_DIR}/{layer}.yaml"
    if not os.path.isfile(yaml_filename):
        if context.log_level <= logging.DEBUG:
            stderr = sys.stderr
        else:
            stderr = asyncio.subprocess.DEVNULL
        layer_extract_process = await asyncio.create_subprocess_shell(
            shlex.join(
                [
                    config.UMODEL_PATH,
                    f"{gameplay_layer_dir}/{layer}.umap",
                    "-game=ue4.24",
                    "-dump",
                ]
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=stderr,
        )
        yaml_content, _ = await layer_extract_process.communicate()

        # fix encoding fuckups caused by umlauts (fuck you harju)
        yaml_content = yaml_content.decode("ISO-8859-1").encode("UTF-8")

        log.debug(yaml_content.decode("UTF-8"))
        _, _, yaml_content = yaml_content.partition(b"---")
        with open(yaml_filename, "wb") as f:
            f.write(yaml_content)
        # help the GC a little
        del yaml_content

    with open(yaml_filename, "r") as f:
        docs = list(yaml.safe_load_all(f))

    # build lane graph from map info
    lane_graph, clusters, mains = get_lane_graph_and_clusters(docs)

    # get map bounds from map info by looking at the two MapTexture objects
    bounds = []
    for obj in docs:
        sdk_name = list(obj.keys())[0]
        _, _, sdk_name = sdk_name.rpartition(".")
        # ignore everything that's not the MapTexture object
        if not sdk_name.startswith("MapTexture"):
            continue
        x, y = absolute_location(access_one(obj)["RootComponent"])
        bounds.append((x, y))

    # we should have exactly two bounding coordinates
    # (e.g., north-east and south-west)
    assert len(bounds) == 2

    # get minimap filename from import table
    # note that some CAF maps use the minimap from vanilla maps, so they
    # don't have a minimap file themself
    minimap_name = None
    table_dump_filename = f"{config.LAYER_DUMP_DIR}/{layer}.tabledump.txt"
    if not os.path.isfile(table_dump_filename):
        table_dump_process = await asyncio.create_subprocess_shell(
            shlex.join(
                [
                    config.UMODEL_PATH,
                    f"{gameplay_layer_dir}/{layer}.umap",
                    "-game=ue4.24",
                    "-list",
                ]
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        table_dump, _ = await table_dump_process.communicate()
        with open(table_dump_filename, "wb") as f:
            f.write(table_dump)

    with open(table_dump_filename, "rb") as f:
        table_dump = f.read().decode("ISO-8859-1")  # again, fucky umlaut encoding

    # extract minimap image (.tga) with umodel
    for name in table_dump.splitlines():
        match = re.match(f"[0-9]+ = .*/Maps/(.*/?(Minimap|Masks)/(.*inimap.*))", name)
        if match is None:
            continue

        minimap_path_in_package, minimap_name = match.group(1, 3)

        # expansions have a slightly different directory structure
        expansion_dirs = ["BlackCoast", "Harju"]
        for ed in expansion_dirs:
            if ed in layer:
                minimap_path_in_package = f"{ed}/{minimap_path_in_package}"
                break

        # skip if minimap already exists
        os.makedirs(config.FULLSIZE_MAP_DIR, exist_ok=True)
        if os.path.isfile(f"{config.FULLSIZE_MAP_DIR}/{minimap_path_in_package}.tga"):
            break
        umodel_cmd = shlex.join(
            [
                config.UMODEL_PATH,
                f"-export",
                f"{map_dir}/{minimap_path_in_package}.uasset",
                f"-game=ue4.24",
                f"-out={config.LAYER_DUMP_DIR}",
            ]
        )

        if context.log_level <= logging.DEBUG:
            stderr = sys.stderr
            stdout = sys.stdout
        else:
            stderr = asyncio.subprocess.DEVNULL
            stdout = asyncio.subprocess.DEVNULL

        map_extract_process = await asyncio.subprocess.create_subprocess_shell(
            umodel_cmd,
            stdout=stdout,
            stderr=stderr,
        )
        assert await map_extract_process.wait() == 0, "map extract failed"

        # ignore maps smaller than 1 MiB
        # (might be a thumbnail)
        if (
            os.stat(f"{config.LAYER_DUMP_DIR}/{minimap_name}.tga").st_size
            < 1 * 1024 * 1024
        ):
            minimap_name = None
            continue
        move_process = await asyncio.subprocess.create_subprocess_shell(
            shlex.join(
                [
                    "mv",
                    f"{config.LAYER_DUMP_DIR}/{minimap_name}.tga",
                    f"{config.FULLSIZE_MAP_DIR}",
                ]
            )
        )
        await move_process.wait()
        break

    # strip out map name from layer name
    is_caf = layer.startswith("CAF_")  # don't strip out CAF prefix
    layer_game_mode_index = layer.casefold().index(game_mode.casefold())
    pretty_layer_name = game_mode + layer[layer_game_mode_index + len(game_mode) :]
    pretty_layer_name = pretty_layer_name.strip()
    pretty_layer_name = pretty_layer_name.replace("_", " ")
    if is_caf:
        pretty_layer_name = "CAF " + pretty_layer_name
    assert pretty_layer_name != ""

    assert (
        minimap_name is not None
    ), f"{pretty_map_name}/{pretty_layer_name} has no minimap"

    layer_data = {
        "background": {
            "corners": [{"x": p[0], "y": p[1]} for p in bounds],
            "minimap_filename": minimap_name,
        },
        "mains": mains,
        "clusters": clusters,
        "lanes": lane_graph,
    }

    return pretty_layer_name, layer_data


async def extract_map(map_dir: str, map_name: str) -> tuple[str, dict]:
    # Some maps have their Gameplay Layers in a subdirectory called Gameplay_Layers.
    # For maps that don't have the Gameplay_Layers subdirectory, all the
    # umap files in the map root directory are gameplay layers.
    # (I hope this doesn't change at some point.
    #  Otherwise we'll try to process lighting layer umap files and will probably
    #  crash at some point.)
    gameplay_layer_dir = f"{map_dir}/{map_name}"
    if "Gameplay_Layers" in os.listdir(gameplay_layer_dir):
        gameplay_layer_dir += "/Gameplay_Layers"

    layers = {}

    # get pretty map name
    MAP_RENAMES = {
        "Al_Basrah_City": "Al Basrah",
        "BASRAH_CITY": "Al Basrah",
        "Belaya": "Belaya Pass",
        "Fallujah_City": "Fallujah",
        "Mestia_Green": "Mestia",
        "BlackCoast": "Black Coast",
    }

    pretty_map_name = map_name
    pretty_map_name = MAP_RENAMES.get(pretty_map_name) or pretty_map_name
    pretty_map_name = pretty_map_name.replace("_", " ")
    assert pretty_map_name != ""

    with log.progress(map_name) as progress:
        for layer in os.listdir(gameplay_layer_dir):
            # ignore non-umap files
            if not layer.endswith(".umap"):
                continue
            layer = layer.replace(".umap", "")

            # only process supported game modes
            game_mode = None
            for gm in GAME_MODES:
                if gm.casefold() in layer.casefold():
                    game_mode = gm
                    break
            if game_mode is None:
                continue

            progress.status(layer)
            pretty_layer_name, layer_data = await extract_layer(
                layer, game_mode, pretty_map_name, gameplay_layer_dir, map_dir
            )

            layers[pretty_layer_name] = layer_data

    return pretty_map_name, layers


async def extract_map_dir(map_dir: str):
    maps = {}

    extraction_runs = []

    for map_name in os.listdir(map_dir):
        # Ignore some unsupported maps
        if (
            not os.path.isdir(f"{map_dir}/{map_name}")
            or "EntryMap" in map_name
            or "Forest" in map_name
            or "Jensens_Range" in map_name
            or "Tutorial" in map_name
            or "Fallujah" == map_name
            or "PacificProvingGrounds" == map_name
        ):
            continue

        extraction_runs.append(extract_map(map_dir, map_name))

    # TODO: this doesn't increase performance at the moment because we're CPU-bound
    #       need to find and optimize the bottleneck (or run multiple processes)
    #       also need to limit the amount of workers probably
    if config.EXTRACT_PARALLEL:
        for pretty_map_name, map_data in await asyncio.gather(*extraction_runs):
            maps[pretty_map_name] = map_data
    else:
        for coro in extraction_runs:
            pretty_map_name, map_data = await coro
            maps[pretty_map_name] = map_data

    return maps


def access_one(obj_dict: dict):
    for key in obj_dict.keys():
        if key != "ClassName":
            return obj_dict[key]
    assert False


def extract():
    os.makedirs(config.LAYER_DUMP_DIR, exist_ok=True)

    if not os.path.isdir(config.UNPACKED_ASSETS_DIR):
        log.error(
            f"Configured UNPACKED_ASSETS_DIR does not exist.\n"
            f"Make sure you run the unpack task first."
        )

    map_dir = config.UNPACKED_ASSETS_DIR + "/Maps"
    with log.progress(f"-- Extracting Maps from {map_dir}"):
        map_data = asyncio.run(extract_map_dir(map_dir))

    with log.progress("-- Writing RAAS data to file"):
        with open(f"raas-data-auto.yaml", "w") as f:
            f.write(yaml.dump(map_data, sort_keys=True, indent=4))
