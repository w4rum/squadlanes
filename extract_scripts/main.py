import os
import re
import subprocess
import sys
from collections import OrderedDict
from pprint import pprint
from typing import Tuple, List, Union, Set

import yaml

UMODEL_PATH = "/home/tim/Desktop/UEViewer/umodel"
SINGLE_LANE_NAME = "Center"

DEBUG = False

GAME_MODES = ["RAAS", "Invasion"]


def add_tuples(*tuples: Tuple):
    s = []
    for elements in zip(*tuples):
        cur_sum = 0
        for e in elements:
            cur_sum += e
        s.append(cur_sum)
    return tuple(s)


def to_list(list_dict: dict):
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
    if cluster_root_dict["ClassName"] in ["BP_CaptureZoneMain_C", "BP_CaptureZone_C", "BP_CaptureZoneInvasion_C"]:
        return [to_capture_point(cluster_root_dict,
                                 cluster_root_dict["ClassName"],
                                 cp_sdk_name({cluster_name: ""}))]
    else:
        assert cluster_root_dict["ClassName"] == "BP_CaptureZoneCluster_C"

    cluster = []
    # iterate over all CPs and only take CPs that have this cluster as parent
    for obj_dict in docs:
        obj = access_one(obj_dict)
        if obj["ClassName"] not in ["BP_CaptureZone_C", "BP_CaptureZoneInvasion_C"]:
            continue
        direct_parent_name = access_one(access_one(obj["DefaultSceneRoot"])["AttachParent"])["OuterName"]
        if direct_parent_name != cluster_name:
            continue
        cluster.append(to_capture_point(obj, obj["ClassName"], cp_sdk_name(obj_dict)))

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
    return {
        "sdk_name": sdk_name,
        "display_name": display_name,
        "x": x,
        "y": y
    }


def absolute_location(scene_root: Union[dict, str]):
    if scene_root == "None":
        return 0, 0

    rel = access_one(scene_root)["RelativeLocation"]
    rel = (rel["X"], rel["Y"])
    attach_parent = access_one(scene_root)["AttachParent"]
    return add_tuples(rel, absolute_location(attach_parent))


def get_lane_graph_and_clusters(docs: List[dict]):
    for obj in docs:
        obj = access_one(obj)
        if obj["ClassName"] == "SQRAASLaneInitializer_C":
            return multi_lane_graph(obj, docs)
        if obj["ClassName"] == "SQGraphRAASInitializerComponent":
            return single_lane_graph(obj, docs)

    assert False


def multi_lane_graph(initializer_dict: dict, docs: List[dict]):
    lane_graph = {}
    cluster_names = set()
    for lane in to_list(initializer_dict["AASLanes"]):
        lane: dict
        # TODO: fix CENTRAL
        # TODO: Lashkar CAF RAAS v1 has single lane '01'
        lane_name = lane["LaneName"].title()
        link_list, pretty_link_list = get_link_list(lane["AASLaneLinks"], docs)
        cluster_names |= get_cluster_names(link_list, docs)
        lane_graph[lane_name] = pretty_link_list
    clusters = get_cluster_list(cluster_names, docs)
    return lane_graph, clusters


def single_lane_graph(initializer_dict: dict, docs: List[dict]):
    link_list, pretty_link_list = get_link_list(initializer_dict["DesignOutgoingLinks"], docs)
    clusters = get_cluster_list(get_cluster_names(link_list, docs), docs)
    lane_graph = {
        SINGLE_LANE_NAME: pretty_link_list,
    }
    return lane_graph, clusters


def prettify_cluster_name(cluster_name):
    pretty = cluster_name.rpartition(".")[2]
    assert pretty != ""
    return pretty


def get_link_list(link_array_dict: dict, docs: List[dict]):
    # transform link list
    links = to_list(link_array_dict)
    links = list(map(lambda link: (sdk_name(link["NodeA"]), sdk_name(link["NodeB"])), links))
    pretty_link_list = list(map(lambda l: {
        "a": prettify_cluster_name(l[0]),
        "b": prettify_cluster_name(l[1])
    }, links))
    return links, pretty_link_list


def get_cluster_names(link_list: List[Tuple[str, str]], docs: List[dict]):
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


def extract_map(map_dir):
    maps = {}
    i = 0
    for map_name in os.listdir(map_dir):
        if not os.path.isdir(f"{map_dir}/{map_name}") \
                or "EntryMap" in map_name \
                or "Forest" in map_name \
                or "Jensens_Range" in map_name \
                or "Tutorial" in map_name \
                or "Fallujah" == map_name:
            continue
        if i > 2 and DEBUG:
            break
        i += 1
        caf = map_name.startswith("CAF")
        gameplay_layer_dir = f"{map_dir}/{map_name}"
        if "Gameplay_Layers" in os.listdir(gameplay_layer_dir):
            gameplay_layer_dir += "/Gameplay_Layers"

        for layer in os.listdir(gameplay_layer_dir):
            if not layer.endswith(".umap"):
                continue
            layer = layer.replace(".umap", "")

            game_mode = None
            for gm in GAME_MODES:
                if gm.casefold() in layer.casefold():
                    game_mode = gm
                    break
            if game_mode is None:
                continue
            print(layer)

            yaml_filename = f"extracts/{layer}.yaml"
            if not os.path.isfile(yaml_filename):
                yaml_content = subprocess.check_output([
                    UMODEL_PATH,
                    f"{gameplay_layer_dir}/{layer}.umap",
                    "-game=ue4.24",
                    "-dump",
                ], stderr=subprocess.DEVNULL)
                _, _, yaml_content = yaml_content.partition(b"---")
                with open(yaml_filename, "wb") as f:
                    f.write(yaml_content)
                del yaml_content

            with open(yaml_filename, "r") as f:
                docs = list(yaml.safe_load_all(f))

            # get lane_graph
            lane_graph, clusters = get_lane_graph_and_clusters(docs)

            # get map bounds
            bounds = []
            for obj in docs:
                sdk_name = list(obj.keys())[0]
                _, _, sdk_name = sdk_name.rpartition(".")
                if not sdk_name.startswith("MapTexture"):
                    continue
                x, y = absolute_location(access_one(obj)["RootComponent"])
                bounds.append((x, y))
            assert len(bounds) == 2

            # extract minimap
            # get filename from import table
            minimap_filename = None
            table_dump_filename = f"extracts/{layer}.tabledump.txt"
            if not os.path.isfile(table_dump_filename):
                table_dump = subprocess.check_output([
                    UMODEL_PATH,
                    f"{gameplay_layer_dir}/{layer}.umap",
                    "-game=ue4.24",
                    "-list",
                ])
                with open(table_dump_filename, "wb") as f:
                    f.write(table_dump)

            with open(table_dump_filename, "r") as f:
                table_dump = f.read()

            for name in table_dump.splitlines():
                match = re.match(f"[0-9]+ = .*/Minimap/(.*inimap.*)", name)
                if match is None:
                    continue
                minimap_filename = match.group(1)
                if os.path.isfile(f"map-resources/full-size/{minimap_filename}.tga"):
                    break
                umodel_cmd = [UMODEL_PATH,
                              "-export",
                              f"{map_dir}/{map_name}/Minimap/{minimap_filename}.uasset",
                              "-out=./extracts"
                              ]
                if caf:
                    umodel_cmd.append("-game=ue4.24")
                subprocess.call(umodel_cmd)
                subprocess.call(["mv",
                                 f"extracts/Maps/{map_name}/Minimap/{minimap_filename}.tga",
                                 f"map-resources/full-size/"
                                 ])
                subprocess.call(["rm",
                                 "-r",
                                 f"extracts/Maps/",
                                 ])
                break

            MAP_RENAMES = {
                "Al_Basrah_City": "Al Basrah",
                "BASRAH_CITY": "Al Basrah",
                "Belaya": "Belaya Pass",
                "Fallujah_City": "Fallujah",
                "Mestia_Green": "Mestia",
            }

            print(map_name)
            pretty_map_name = map_name
            if caf:
                _, _, pretty_map_name = pretty_map_name.partition("CAF_")
            pretty_map_name = MAP_RENAMES.get(pretty_map_name) or pretty_map_name
            pretty_map_name = pretty_map_name.replace("_", " ")

            # strip out map name from layer name
            layer_game_mode_index = layer.casefold().index(game_mode.casefold())
            pretty_layer_name = game_mode + layer[layer_game_mode_index + len(game_mode):]
            pretty_layer_name = pretty_layer_name.strip()
            pretty_layer_name = pretty_layer_name.replace("_", " ")
            print(pretty_map_name)
            assert pretty_map_name != ""
            assert pretty_layer_name != ""

            if minimap_filename is None:
                print(f"[WARN] {pretty_map_name}/{pretty_layer_name} has no minimap")

            if caf:
                pretty_layer_name = "CAF " + pretty_layer_name

            layer_data = {
                "background": {
                    "corners": [
                        {"x": p[0], "y": p[1]}
                        for p in bounds
                    ],
                    "minimap_filename": minimap_filename,
                    "heightmap_filename": f"height-map-{pretty_map_name.rpartition(' ')[0].lower()}C1",
                    "heightmap_transform": {
                        "shift_x": 0,
                        "shift_y": 0,
                        "scale_x": 1.0,
                        "scale_y": 1.0,
                    }
                },
                "clusters": clusters,
                "lanes": lane_graph,
            }

            if pretty_map_name not in maps:
                maps[pretty_map_name] = {}
            maps[pretty_map_name][pretty_layer_name] = layer_data

    return maps


def access_one(obj_dict: dict):
    for key in obj_dict.keys():
        if key != "ClassName":
            return obj_dict[key]
    assert False


def main():
    map_dirs = [
        "/mnt/win/Program Files/Epic Games/SquadEditor/Squad/Content/Maps",
        "/home/tim/Downloads/squad-dump/SquadGame/Plugins/Mods/CanadianArmedForces/Content/Maps",
    ]

    os.makedirs("extracts", exist_ok=True)

    map_data = {}
    for cur_dir in map_dirs:
        cur_data = extract_map(cur_dir)
        for map_name in cur_data.keys():
            if map_name not in map_data:
                map_data[map_name] = cur_data[map_name]
            else:
                map_data[map_name].update(cur_data[map_name])

    with open(f"raas-data-auto.yaml", "w") as f:
        f.write(yaml.dump(map_data, sort_keys=True, indent=4))


if __name__ == "__main__":
    main()
