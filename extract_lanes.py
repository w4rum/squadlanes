import os
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import Tuple

import yaml


@dataclass()
class CapturePoint:
    sdk_name: str
    full_sdk_filename: str
    lane: str
    depth: int
    x: float
    y: float


def add_tuples(*tuples: Tuple):
    s = []
    for elements in zip(*tuples):
        cur_sum = 0
        for e in elements:
            cur_sum += e
        s.append(cur_sum)
    return tuple(s)


def is_root_node_name(name: str):
    return name.startswith("BP_RAAS") \
           and "." not in name \
           and not name.endswith("_C")


def is_cluster_name(name):
    return "CaptureZoneCluster" in name \
           and "." not in name \
           and not name.endswith("_C")


def camel_case_to_spaced_title(name):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1 \2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1 \2', name)


def components(layer_dir):
    return os.listdir(layer_dir)


def capture_points(layer_dir):
    _, _, layer_name = layer_dir.rpartition("/")[0].rpartition("/")

    for entry in components(layer_dir):
        entry_dir = f"{layer_dir}/{entry}"
        if not os.path.isdir(entry_dir):
            continue

        cur_renames = None
        for cur_map in RENAMES.keys():
            if layer_name.startswith(cur_map):
                cur_renames = RENAMES[cur_map]
                break

        if entry.endswith(".BP_CaptureZone_C"):
            continue

        # get depth, lane, and name
        if cur_renames is not None \
                and entry in cur_renames:
            renamed_entry = cur_renames[entry]
        else:
            renamed_entry = entry
        match = re.match(r"(0[0-9]|100)([CNESWab]|Red|Yellow|Green|Blue)?-(.*)", renamed_entry)
        if match is None:
            continue

        depth, lane, name = match.group(1, 2, 3)
        depth = int(depth)

        # ignore cluster points
        if is_cluster_name(name):
            continue

        # get root coordinates
        for comp in components(layer_dir):
            if not is_root_node_name(comp):
                continue

            with open(f"{layer_dir}/{comp}/RootComponent.SceneComponent",
                      "rb") as f:
                f.seek(OFFSET_CP_ROOT)
                x, y, _ = struct.unpack("<fff", f.read(12))
                root_pos = (x, y)

        # get position of cluster point (unless it's main)
        if depth in [0, 100]:
            cluster_pos_relative = (0.0, 0.0)
        else:
            # get cluster name
            cluster_name = None
            c = components(layer_dir)
            for n in components(layer_dir):
                if not is_cluster_name(n):
                    continue
                if not n.startswith(f"0{depth}{lane or ''}"):
                    continue
                cluster_name = n
                break
            if cluster_name is None:
                #print(f"[WARN] {layer_dir}/{entry} has no cluster")
                cluster_pos_relative = (0.0, 0.0)
            else:
                with open(f"{layer_dir}/{cluster_name}/"
                          f"DefaultSceneRoot.SceneComponent", "rb") as f:
                    f.seek(OFFSET_CP_OTHER)
                    x, y, _ = struct.unpack("<fff", f.read(12))
                    cluster_pos_relative = (x, y)

        # get position of this capture point
        with open(f"{layer_dir}/{entry}/"
                  f"DefaultSceneRoot.SceneComponent", "rb") as f:
            f.seek(OFFSET_CP_OTHER)
            x, y, _ = struct.unpack("<fff", f.read(12))
            cur_pos_relative = (x, y)
        x, y = add_tuples(root_pos, cluster_pos_relative, cur_pos_relative)

        yield CapturePoint(sdk_name=name, full_sdk_filename=entry, lane=lane, depth=depth, x=x, y=y)


def proper_lane_name(lane_name):
    return {
        "C": "Central",
        "E": "East",
        "W": "West",
        "N": "North",
        "S": "South",
        "Red": "Red",
        "Green": "Green",
        "Blue": "Blue",
        "Yellow": "Yellow",
        "a": "Alpha",
        "b": "Bravo",
    }[lane_name]


OFFSET_CP_ROOT = 0x31
OFFSET_CP_OTHER = 0x4E
OFFSET_CORNER = 0x31

# un-fuck naming inconsistencies
RENAMES = {
    "Mestia": {
        "04-CrucibleAlpha": "03-CrucibleAlpha",
        "04-CrucibleBravo": "03-CrucibleBravo",
    },
}


def get_lanes(layer_dir: str):
    # collect all lane names
    lane_graph = {}
    for cp in capture_points(layer_dir):
        if cp.lane is not None and cp.lane not in lane_graph:
            lane_graph[cp.lane] = {}
    # if the map only has lane-less CPs, create a single lane called Central
    if len(lane_graph) == 0:
        lane_graph["C"] = {}

    for cp in capture_points(layer_dir):
        if cp.lane is None:
            affected_lanes = lane_graph.keys()
        else:
            affected_lanes = [cp.lane]

        for lane in affected_lanes:
            if cp.depth not in lane_graph[lane]:
                lane_graph[lane][cp.depth] = {}
            lane_graph[lane][cp.depth][cp.sdk_name] = {
                "display_name": camel_case_to_spaced_title(cp.sdk_name),
                "x": cp.x,
                "y": cp.y,
            }

    # correct depth of far main
    for lane in lane_graph:
        if 100 not in lane_graph[lane]:
            continue
        main = lane_graph[lane][100]
        del lane_graph[lane][100]
        highest_depth = max(lane_graph[lane].keys())
        lane_graph[lane][highest_depth + 1] = main

    # rename lanes
    for lane in list(lane_graph.keys()):
        lane_data = lane_graph[lane]
        del lane_graph[lane]
        lane_graph[proper_lane_name(lane)] = lane_data

    return lane_graph


map_dir = "/mnt/win/Program Files/Epic Games/SquadEditor/Squad/Content/Maps"
os.makedirs("extracts", exist_ok=True)
os.makedirs("raas-lanes", exist_ok=True)

maps = {}

for map_name in os.listdir(map_dir):
    if not os.path.isdir(f"{map_dir}/{map_name}") \
            or "EntryMap" in map_name \
            or "Forest" in map_name \
            or "Jensens_Range" in map_name \
            or "Tutorial" in map_name \
            or "Fallujah" == map_name:
        continue
    for layer in os.listdir(f"{map_dir}/{map_name}/Gameplay_Layers"):
        if "RAAS" not in layer:
            continue
        assert layer.endswith(".umap")
        layer = layer.replace(".umap", "")
        # extract files
        if not os.path.isdir(f"extracts/{layer}"):
            print(f"Extracting: {layer}")
            subprocess.call(["wine",
                             "extract.exe",
                             "-extract",
                             f"{map_dir}/{map_name}/Gameplay_Layers/{layer}.umap",
                             "-out=extracts"
                             ])
        else:
            print(f"Using cached extract: {layer}")

        # get lane_graph
        layer_dir = f"extracts/{layer}/{layer}/PersistentLevel"
        lane_graph = get_lanes(layer_dir)

        # get map bounds
        bounds = []
        for entry in os.listdir(f"{layer_dir}"):
            if "MapTextureCorner" not in entry \
                    or "." in entry:
                continue
            for comp_file in os.listdir(f"{layer_dir}/{entry}"):
                if not comp_file.endswith(".SceneComponent"):
                    continue
                if not comp_file.startswith("DefaultSceneRoot") \
                        and not comp_file.startswith("SceneComp"):
                    print(f"[ERROR] Unknown comp: "
                          f"{layer_dir}/{entry}/{comp_file}")
                    sys.exit(1)
                with open(f"{layer_dir}/{entry}/{comp_file}", "rb") as f:
                    f.seek(OFFSET_CORNER)
                    x, y, _ = struct.unpack("<fff", f.read(12))
                    bounds.append((x, y))

        # extract minimap
        with open(f"extracts/{layer}/NameTable.txt", "r") as f:
            nametable = f.readlines()
        minimap_filename = None
        for name in nametable:
            match = re.match(f"[0-9]+ = \"/Game/Maps/{map_name}/Minimap/(.*inimap.*)\"", name)
            if match is None:
                continue
            minimap_filename = match.group(1)
            if os.path.isfile(f"map-resources/full-size/{minimap_filename}.tga"):
                break
            subprocess.call(["./umodel",
                             "-export",
                             f"{map_dir}/{map_name}/Minimap/{minimap_filename}.uasset",
                             "-out=./extracts"
                             ])
            subprocess.call(["mv",
                             f"extracts/Maps/{map_name}/Minimap/{minimap_filename}.tga",
                             f"map-resources/full-size/"
                             ])
            subprocess.call(["rm",
                             "-r",
                             f"extracts/Maps/",
                             ])
            break


        layer_data = {
            "background": {
                "corners": [
                    {"x": p[0], "y": p[1]}
                    for p in bounds
                ],
                "x_stretch_factor": 1.0,
                "y_stretch_factor": 1.0,
                "minimap_filename": minimap_filename,
            },
            "lanes": lane_graph,
        }

        map_simple_name, _, map_layer_name = layer.rpartition("_RAAS_")
        map_layer_name = "RAAS " + map_layer_name
        if map_simple_name not in maps:
            maps[map_simple_name] = {}
        maps[map_simple_name][map_layer_name] = layer_data

        # with open(f"raas-lanes/{layer}.json", "w") as f:
        #    json.dump(layer_data, f, sort_keys=True, indent=4)

with open(f"raas-data-auto.yaml", "w") as f:
    f.write(yaml.dump(maps, sort_keys=True, indent=4))
