import asyncio
import glob
import math
import os
import re
import shlex
import shutil
import struct
import sys
from typing import Tuple, List, Union, Set, Any

import yaml
from tqdm.asyncio import tqdm

from squadlanes_extraction import config

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

SINGLE_LANE_NAME = "Center"

GAME_MODES = ["RAAS", "Invasion"]

# todo: fix parallelism
#       at the moment, this does not improve performance
#       and simply makes debugging harder
# parallel_limit = asyncio.Semaphore(config.MAXIMUM_PARALLEL_TASKS)
parallel_limit = asyncio.Semaphore(1)


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

    If there are holes in the dict, then the items will be compacted.

    Example:
    { "0": "A", "1": "B", "2": "C" } => ["A", "B", "C"]

    { "0": "A", "2": "C" } => ["A", "C"]
    """
    items = list(list_dict.items())
    items.sort(key=lambda it: it[0])
    return [it[1] for it in items]


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
        assert cluster_root_dict["ClassName"] in [
            "BP_CaptureZoneCluster_C",
            "HLP_BP_CaptureZoneClusterLattice_C",
        ]

    cluster = []
    # iterate over all CPs and only take CPs that have this cluster as parent
    for obj_dict in docs:
        obj = access_one(obj_dict)
        if obj["ClassName"] not in ["BP_CaptureZone_C", "BP_CaptureZoneInvasion_C"]:
            continue
        scene_root = access_one(obj["DefaultSceneRoot"])
        parent = scene_root["AttachParent"]
        if parent == "None":
            continue

        direct_parent_name = access_one(parent)["OuterName"]
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


def get_main_cps(docs: dict) -> list[str]:
    # identify main clusters
    mains = []
    for obj in docs:
        if access_one(obj)["ClassName"] != "BP_CaptureZoneMain_C":
            continue
        mains.append(cp_sdk_name(obj))
    assert len(mains) == 2, f"found {len(mains)} main bases"

    mains.sort()
    return mains


def get_lane_graph_and_clusters(docs: List[dict]):
    # get lane graph and clusters
    handlers = {
        # numbers define priorities
        # HLP GRAAS also has the multi_lane_graph initializer, so we check for both
        "SQRAASLaneInitializer_C": (0, multi_lane_graph),
        "SQGraphRAASInitializerComponent": (0, single_lane_graph),
        "SQRAASGridInitializer_C": (1, hlp_graas),
        "HLP_SQRAASLatticeInitializer_C": (1, hlp_lattice),
    }
    priority = -1
    handler = None
    initializer = None

    for obj in docs:
        obj = access_one(obj)
        class_name = obj["ClassName"]

        cur_priority, cur_handler = handlers.get(class_name, (-1, None))
        if cur_priority > priority:
            priority = cur_priority
            handler = cur_handler
            initializer = obj

    assert handler is not None, "no supported RAAS initializer found"
    lane_graph, clusters, logic_name = handler(initializer, docs)

    mains = get_main_cps(docs)

    return lane_graph, clusters, mains, logic_name


def is_single_path(link_list: dict, docs: dict) -> bool:
    # Traverse the link list once to distinguish between a lane with a single path
    # or a branching lane.
    # Note that the path traversal logic is the same (directed source-sink graph).

    # there is only one path is every node (except mains) has
    # in-degree 1 and out-degree 1

    # check that every node only appear once on the
    # a-side and once on the b-side of a link

    cluster_names = get_cluster_names(link_list)
    main_clusters = get_main_clusters(link_list, docs)

    missing_out_link = set(cluster_names)
    missing_in_link = set(cluster_names)

    single_lane = True
    for a, b in link_list:
        if a not in missing_out_link or b not in missing_in_link:
            single_lane = False
        missing_out_link.discard(a)
        missing_in_link.discard(b)

    # make sure one of the mains has 1-out-0-in and vice versa
    if main_clusters[0] in missing_in_link:
        source_main = main_clusters[0]
        dest_main = main_clusters[1]
    else:
        dest_main = main_clusters[0]
        source_main = main_clusters[1]

    if not (
        source_main in missing_in_link
        and source_main not in missing_out_link
        and dest_main not in missing_in_link
        and dest_main in missing_out_link
    ):
        single_lane = False

    for main_cl in main_clusters:
        missing_out_link.discard(main_cl)
        missing_in_link.discard(main_cl)

    # if there are still nodes left in missing_out_link and missing_in_link, then they
    # are disconnected from the mains
    # => warn but don't count
    if len(missing_in_link) > 0 or len(missing_out_link) > 0:
        print(f"Warning: Isolated clusters found:")
        print(missing_out_link.union(missing_in_link))

    return single_lane


def multi_lane_graph(initializer_dict: dict, docs: List[dict]):
    lane_graph = {}
    lane_link_lists = {}
    cluster_names = set()
    for lane in index_dict_to_list(initializer_dict["AASLanes"]):
        lane: dict
        lane_name = lane["LaneName"].title()
        link_list, pretty_link_list = get_link_list(lane["AASLaneLinks"])
        cluster_names |= get_cluster_names(link_list)
        lane_graph[lane_name] = pretty_link_list
        lane_link_lists[lane_name] = link_list

    # if there is only one lane, and it's a path, then display "Single Lane" as logic
    if len(lane_link_lists) == 1 and is_single_path(
        list(lane_link_lists.values())[0], docs
    ):
        logic = "Single Lane"
    else:
        logic = "Multiple Lanes"

    clusters = get_cluster_list(cluster_names, docs)
    return lane_graph, clusters, logic


def get_main_clusters(link_list: dict, docs: dict) -> list[str]:
    cluster_names = get_cluster_names(link_list)
    clusters = {name: to_cluster(name, docs) for name in cluster_names}

    main_cps = get_main_cps(docs)
    main_clusters = []

    for cluster_name, cluster in clusters.items():
        for cp in cluster:
            if cp["sdk_name"] in main_cps:
                main_clusters.append(cluster_name)

    return main_clusters


def single_lane_graph(initializer_dict: dict, docs: List[dict]):
    link_list, pretty_link_list = get_link_list(initializer_dict["DesignOutgoingLinks"])

    logic = "Single Lane" if is_single_path(link_list, docs) else "No Lanes"

    clusters = get_cluster_list(get_cluster_names(link_list), docs)
    lane_graph = {
        SINGLE_LANE_NAME: pretty_link_list,
    }
    return lane_graph, clusters, logic


def hlp_graas(initializer_dict: dict, docs: List[dict]):
    # build link list
    team_1_main = sdk_name(initializer_dict["Team1Main"])
    team_2_main = sdk_name(initializer_dict["Team2Main"])

    # convert AASGrids to better layered graph structure
    # ("layered" as in "has multiple layers", not as in "Squad map layer")
    # (will use "depth" as a synonym for "layer" to avoid confusion)
    depths: list[list[str]] = []
    aas_grids: list = index_dict_to_list(initializer_dict["AASGrids"])
    for grid in aas_grids:
        cur_layer = []
        possible_clusters = index_dict_to_list(grid["PossibleClusters"])
        for cluster in possible_clusters:
            cur_layer.append(sdk_name(cluster))
        depths.append(cur_layer)

    links = []

    # link main 1 -> depth 0
    for cluster in depths[0]:
        links.append((team_1_main, cluster))

    # link depth i -> depth i+1
    # in GRAAS, a cluster can either jump
    # - forwards (depth+1, same cluster index)
    # - diagonally (depth+1, cluster index -1 or +1)
    # that means that clusters that are more than 1 step horizontally can't be reached)
    # TODO: don't ignore probabilities here
    #       the SQRAASGridInitializer has a "Jump Chance"
    #       going diagonally has Jump Chance %
    #       going forward has (1 - Jump Chance) %
    #       on a diagonal move, which of the neighbours is jumped to is
    #           50/50 if there are two neighbours
    #           100 if there is only one neighbour (we're at an edge)
    #       this means that edge CPs are probably less likely since we're 2/3 likely
    #       to jump away from an edge
    for di, cur_depth in enumerate(depths[:-1]):
        for ci, cluster in enumerate(cur_depth):
            for ci_delta in [-1, 0, 1]:
                if ci + ci_delta < 0:
                    continue
                if ci + ci_delta >= len(depths[di + 1]):
                    continue

                links.append((cluster, depths[di + 1][ci + ci_delta]))

    # link depth n -> main 2
    for cluster in depths[-1]:
        links.append((cluster, team_2_main))

    clusters = get_cluster_list(get_cluster_names(links), docs)
    lane_graph = {
        SINGLE_LANE_NAME: prettify_link_list(links),
    }
    return lane_graph, clusters, "Lane Hopping"


def hlp_lattice(initializer_dict: dict, docs: List[dict]):
    team_1_main = sdk_name(initializer_dict["Team1Main"])
    team_2_main = sdk_name(initializer_dict["Team2Main"])

    # lattice has the same logic as single_lane_graph
    # but the links aren't stored in a central list.
    # instead, each cluster lists its own neighbours
    links = []

    # link main 1 -> first clusters
    first_clusters = index_dict_to_list(initializer_dict["FirstClusters"])
    for cluster in first_clusters:
        links.append((team_1_main, sdk_name(cluster)))

    # remaining links
    # look through all clusters and add neighbours
    for obj in docs:
        # ignore non-cluster assets
        class_name = access_one(obj)["ClassName"]
        if class_name != "HLP_BP_CaptureZoneClusterLattice_C":
            continue

        cluster = sdk_name(obj)

        next_clusters = access_one(obj)["NextClusters"]

        # if there are no neighbours, we're at the end and need to link to main 2
        if len(next_clusters) == 0:
            links.append((cluster, team_2_main))
            continue

        neighbours = index_dict_to_list(next_clusters)
        for nb in neighbours:
            links.append((cluster, sdk_name(nb)))

    # there might be some unreachable clusters due to errors by hawk
    # Squad won't care about them, but we want to explicitly remove them
    # to avoid fuckups in the interface
    clusters = get_cluster_names(links)
    no_outgoing_edges = set(clusters)
    no_incoming_edges = set(clusters)
    for a, b in links:
        no_outgoing_edges.discard(a)
        no_incoming_edges.discard(b)
    no_outgoing_edges.discard(team_1_main)
    no_outgoing_edges.discard(team_2_main)
    no_incoming_edges.discard(team_1_main)
    no_incoming_edges.discard(team_2_main)

    broken_clusters = no_outgoing_edges.union(no_incoming_edges)
    links = [
        (a, b)
        for a, b in links
        if a not in broken_clusters and b not in broken_clusters
    ]

    # TODO: dedup
    clusters = get_cluster_list(get_cluster_names(links), docs)
    lane_graph = {
        SINGLE_LANE_NAME: prettify_link_list(links),
    }
    return lane_graph, clusters, "No Lanes"


def prettify_cluster_name(cluster_name):
    pretty = cluster_name.rpartition(".")[2]
    assert pretty != ""
    return pretty


def prettify_link_list(links: list[tuple[str, str]]) -> list[dict[str, str]]:
    return list(
        map(
            lambda l: {
                "a": prettify_cluster_name(l[0]),
                "b": prettify_cluster_name(l[1]),
            },
            links,
        )
    )


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

    pretty_link_list = prettify_link_list(links)

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


async def extract_yaml_dump(full_layer_path: str, layer_filename: str) -> list[dict]:
    # extract map information from umap with umodel
    yaml_filename = f"{config.LAYER_DUMP_DIR}/{layer_filename}.yaml"
    if not os.path.isfile(yaml_filename):
        if config.LOG_LEVEL == "DEBUG":
            stderr = sys.stderr
        else:
            stderr = asyncio.subprocess.DEVNULL
        layer_extract_process = await asyncio.create_subprocess_shell(
            shlex.join(
                [
                    config.UMODEL_PATH,
                    full_layer_path,
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

        _, _, yaml_content = yaml_content.partition(b"---")
        with open(yaml_filename, "wb") as f:
            f.write(yaml_content)
        # help the GC a little
        del yaml_content

    with open(yaml_filename, "r") as f:
        docs = list(yaml.safe_load_all(f))

    return docs


async def extract_minimap_bounds(
    docs: list[dict],
) -> tuple[tuple[float, float], tuple[float, float]]:
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

    return tuple(bounds)


async def extract_table_dump(full_layer_path: str, layer_filename: str) -> str:
    table_dump_filename = f"{config.LAYER_DUMP_DIR}/{layer_filename}.tabledump.txt"

    # create table dump using umodel
    if not os.path.isfile(table_dump_filename):
        table_dump_process = await asyncio.create_subprocess_shell(
            shlex.join(
                [
                    config.UMODEL_PATH,
                    full_layer_path,
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

    return table_dump


def convert_minimap_partial_path(
    minimap_partial_path: str, unpacked_assets_dir: str
) -> str:
    # This part is a bit tricky.
    # The minimap_partial_path is actually not a valid path.
    #
    # First of all, it starts with a seemingly arbitrary name identifying the bundle
    # its in.
    # For vanilla core assets, this is "Game".
    # For Black Coast, it is "BlackCoast", and for Harju, it is "Harju".
    # HLP uses the vanilla minimaps, so it simply follows the above rules.
    #
    # Examples:
    # /Game/Maps/Chora/Minimap/Chora_Minimap.uasset
    # /BlackCoast/Maps/Minimap/Black_Coast_Minimap.uasset
    # /Harju/Maps/Minimap/Harju_Minimap.uasset
    #
    # None of these match actual directories.
    #
    # In order to find the correct path, we strip out the first part of the part.
    # Afterwards, we try to find a file that has the partial path as a suffix.

    partial_parts = path_split_recursive(minimap_partial_path)

    # remove the leading "/" and the first directory part
    partial_parts = partial_parts[2:]

    # go through all unpacked assets ending with .uasset
    minimap_full_path = None
    assets_list = glob.glob("**/*.uasset", root_dir=unpacked_assets_dir, recursive=True)
    for asset_path in assets_list:
        full_parts = path_split_recursive(asset_path)

        # turn the paths around and check if all parts match
        # (discarding the extra parts from the full path)
        matched_parts = zip(reversed(full_parts), reversed(partial_parts))
        if all([a == b for a, b in matched_parts]):
            minimap_full_path = os.path.join(unpacked_assets_dir, asset_path)
            break

    assert (
        minimap_full_path is not None
    ), f"can't find minimap asset: {minimap_partial_path}"

    return minimap_full_path


async def extract_minimap(
    unpacked_assets_dir: str,
    layer_filename: str,
    table_dump: str,
) -> str:
    minimap_name = None

    # go through the table dump to find the correct asset
    for name in table_dump.splitlines():
        # ignore all lines that don't match what we expect the minimap path to look like
        match = re.match(f"[0-9]+ = (.*(/Minimap|/Masks)/(.*inimap.*))", name)
        if match is None:
            continue

        minimap_partial_path, minimap_name = match.group(1, 3)
        minimap_partial_path += ".uasset"

        # the path in the table dump isn't a valid path; need to convert
        minimap_full_path = convert_minimap_partial_path(
            minimap_partial_path, unpacked_assets_dir
        )

        # extract that asset
        target_path = f"{config.FULLSIZE_MAP_DIR}/{minimap_name}.tga"
        await extract_minimap_asset(minimap_full_path, target_path)

        # ignore maps smaller than 1 MiB
        # (might be a thumbnail)
        if os.stat(target_path).st_size < 1 * 1024 * 1024:
            os.remove(target_path)
            minimap_name = None
            continue

        break

    assert (
        minimap_name is not None
    ), f"can't find minimap in table dump for {layer_filename}"

    return minimap_name


async def extract_minimap_asset(asset_path: str, target_path: str):
    # skip if minimap already exists
    if os.path.isfile(target_path):
        return

    # need to unpack in a temp dir because umodel creates nested directories instead
    # of just a single file
    temp_dir = os.path.join(config.FULLSIZE_MAP_DIR, "tmp")
    os.makedirs(temp_dir, exist_ok=True)

    umodel_cmd = shlex.join(
        [
            config.UMODEL_PATH,
            f"-export",
            asset_path,
            f"-game=ue4.24",
            f"-out={temp_dir}",
        ]
    )

    if config.LOG_LEVEL == "DEBUG":
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

    # move the extracted image to the top level
    tga_list = glob.glob("**/*.tga", root_dir=temp_dir, recursive=True)

    # this will probably crash and burn when I parallelize things
    assert len(tga_list) == 1, "minimap uasset has is more than one file, wtf?"

    tga_path = tga_list[0]
    tga_filename = os.path.split(tga_path)[1]

    os.rename(
        os.path.join(temp_dir, tga_path),
        os.path.join(config.FULLSIZE_MAP_DIR, tga_filename),
    )

    shutil.rmtree(temp_dir)


async def extract_layer(
    unpacked_assets_dir: str,
    layer_path: str,
) -> dict:
    async with parallel_limit:
        if config.LOG_LEVEL == "debug":
            print(layer_path)

        layer_filename, pretty_map_name, pretty_layer_name = extract_pretty_names(
            layer_path
        )

        full_layer_path = os.path.join(unpacked_assets_dir, layer_path)

        docs = await extract_yaml_dump(full_layer_path, layer_filename)

        # build lane graph from map info
        lane_graph, clusters, mains, logic = get_lane_graph_and_clusters(docs)

        bounds = await extract_minimap_bounds(docs)

        table_dump = await extract_table_dump(full_layer_path, layer_filename)

        # get minimap filename from import table
        minimap_name = await extract_minimap(
            unpacked_assets_dir, layer_filename, table_dump
        )

        return {
            pretty_map_name: {
                pretty_layer_name: {
                    "background": {
                        "corners": [{"x": p[0], "y": p[1]} for p in bounds],
                        "minimap_filename": minimap_name,
                    },
                    "logic": logic,
                    "mains": mains,
                    "clusters": clusters,
                    "lanes": lane_graph,
                }
            }
        }


def path_split_recursive(path: str) -> list[str]:
    parts = []
    head = path

    while head != "" and head != "/":
        head, tail = os.path.split(head)
        parts.insert(0, tail)

    if head == "/":
        parts.insert(0, head)

    return parts


def extract_pretty_names(layer_path: str) -> tuple[str, str, str]:
    path_parts = path_split_recursive(layer_path)

    layer_filename = path_parts[-1]
    match = re.match(r"(HLP_)?(.*)_([gG]?RAAS|Invasion)_(.*)\.umap", layer_filename)
    hlp_prefix, map_name, gamemode, version = match.group(1, 2, 3, 4)

    # replace GRAAS with RAAS (hawk's request)
    gamemode = gamemode.replace("GRAAS", "RAAS").replace("gRAAS", "RAAS")

    # sometimes the version has _Flooded or _Night as a suffix
    version = version.replace("_", " ")

    # execute hard-coded map renames
    MAP_RENAMES = {
        "Albasrah": "Al Basrah",
        "Belaya": "Belaya Pass",
        "Kamdesh": "Kamdesh Highlands",
        "Kokan": "Kokan Valley",
        "Lashkar": "Lashkar Valley",
        "Logar": "Logar Valley",
        "Manic": "Manic-5",
        "Tallil": "Tallil Outskirts",
    }
    pretty_map_name = MAP_RENAMES.get(map_name, map_name).replace("_", " ")

    # turn PascalCase into space-separated title case
    # ex: GooseBay -> Goose Bay
    pretty_map_name = re.sub(r"(?<!^)(?=[A-Z])", " ", pretty_map_name).title()
    # remove double-spaces possibly introduced by above
    pretty_map_name = pretty_map_name.replace("  ", " ")

    pretty_layer_name = f"{gamemode} {version}"
    if hlp_prefix is not None:
        pretty_layer_name = "HLP " + pretty_layer_name

    return layer_filename, pretty_map_name, pretty_layer_name


def dict_update_2_deep(base_dict: dict[Any, dict], update_dict: dict[Any, dict]):
    for k, v in update_dict.items():
        if k in base_dict:
            base_dict[k].update(v)
        else:
            base_dict[k] = v


async def extract_maps(unpacked_assets_dir: str) -> dict:
    raas_data = {}

    extraction_runs = []

    layers_list = glob.glob(
        "**/Gameplay_Layers/*.umap", root_dir=unpacked_assets_dir, recursive=True
    )

    for layer_path in layers_list:
        # Ignore some unsupported maps and irrelevant assets
        unsupported_maps = [
            "Jensens_Range",
            "PacificProvingGrounds",
            "Dummy",
            "Sound",
        ]
        if any([map_name in layer_path for map_name in unsupported_maps]):
            continue

        # Ignore all unsupported game modes
        supported_gamemodes = [
            "RAAS",
            "Invasion",
            "GRAAS",
        ]
        if not any(
            [game_mode_name in layer_path for game_mode_name in supported_gamemodes]
        ):
            continue

        # ignore HLP night maps (they're the same as the day maps)
        if "HLP" in layer_path and "Night" in layer_path:
            continue

        extraction_runs.append(extract_layer(unpacked_assets_dir, layer_path))

    # run parallel
    # TODO: this doesn't increase performance at the moment because we're CPU-bound
    #       need to find and optimize the bottleneck (or run multiple processes)
    #       also, this is currently bugged and seems to freeze, so we force
    #       sequential operation for now

    # if config.EXTRACT_PARALLEL:
    #     for pretty_map_name, map_data in await tqdm.gather(*extraction_runs):
    #         maps[pretty_map_name] = map_data
    # else:

    for coro in tqdm(extraction_runs):
        layer_data = await coro
        dict_update_2_deep(raas_data, layer_data)

    return raas_data


def access_one(obj_dict: dict):
    for key in obj_dict.keys():
        if key != "ClassName":
            return obj_dict[key]
    assert False


def extract():
    os.makedirs(config.LAYER_DUMP_DIR, exist_ok=True)

    unpacked_assets_dir = os.path.abspath(config.UNPACKED_ASSETS_DIR)

    if not os.path.isdir(unpacked_assets_dir):
        print(
            f"Configured UNPACKED_ASSETS_DIR does not exist.\n"
            f"Make sure you run the unpack task first."
        )
        return

    map_data = asyncio.run(extract_maps(unpacked_assets_dir), debug=True)

    with open(f"raas-data-auto.yaml", "w") as f:
        f.write(yaml.dump(map_data, sort_keys=True, indent=4))


if __name__ == "__main__":
    extract()
