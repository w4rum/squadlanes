import json
import os
import re
import struct
import subprocess
import sys
from typing import Tuple, List


def add_tuples(*tuples: List[Tuple]):
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
    _, _, layer_name = layer_dir.rpartition("/")[0].rpartition("/")
    cur_renames = None
    for cur_map in RENAMES.keys():
        if layer_name.startswith(cur_map):
            cur_renames = RENAMES[cur_map]
            break

    components = os.listdir(layer_dir)

    # get root coordinates
    for entry in components:
        if not is_root_node_name(entry):
            continue
        with open(f"{layer_dir}/{entry}/RootComponent.SceneComponent",
                  "rb") as f:
            f.seek(OFFSET_CP_ROOT)
            root_pos = struct.unpack("<fff", f.read(12))

    # collect capture points
    lane_graph = {}
    for entry in components:
        entry_dir = f"{layer_dir}/{entry}"
        if not os.path.isdir(entry_dir):
            continue

        # get depth, lane, and name
        if cur_renames is not None \
                and entry in cur_renames:
            renamed_entry = cur_renames[entry]
        else:
            renamed_entry = entry
        match = re.match(r"(0[0-9]|100)([CNESW]?)-(.*)", renamed_entry)
        if match is None:
            continue

        depth, lane, name = match.group(1, 2, 3)
        depth = int(depth)

        # ignore cluster points
        if is_cluster_name(name):
            continue

        # add to lane graph
        if depth not in lane_graph:
            lane_graph[depth] = {}
        if lane not in lane_graph[depth]:
            lane_graph[depth][lane] = []

        # get position of cluster point (unless it's main)
        print(entry)
        if depth not in [0, 100]:
            # get cluster name
            cluster_name = None
            for n in components:
                if not is_cluster_name(n):
                    continue
                if not n.startswith(f"0{depth}{lane}"):
                    continue
                cluster_name = n
                break
            if cluster_name is None:
                print(f"[WARN] {layer_name}/{entry} has no cluster")
                cluster_pos_relative = (0, 0, 0)
            else:
                with open(f"{layer_dir}/{cluster_name}/"
                          f"DefaultSceneRoot.SceneComponent", "rb") as f:
                    f.seek(OFFSET_CP_OTHER)
                    cluster_pos_relative = struct.unpack("<fff", f.read(12))
        else:
            cluster_pos_relative = (0, 0, 0)

        # get position of this capture point
        with open(f"{layer_dir}/{entry}/"
                  f"DefaultSceneRoot.SceneComponent", "rb") as f:
            f.seek(OFFSET_CP_OTHER)
            cur_pos_relative = struct.unpack("<fff", f.read(12))
        pos = add_tuples(root_pos, cluster_pos_relative, cur_pos_relative)

        lane_graph[depth][lane].append({
            "name": name,
            "pos": pos
        })
    # correct depth of far main
    main = lane_graph[100]
    del lane_graph[100]
    highest_depth = max(lane_graph.keys())
    lane_graph[highest_depth + 1] = main
    return lane_graph


map_dir = "/mnt/win/Program Files/Epic Games/SquadEditor/Squad/Content/Maps"
os.makedirs("extracts", exist_ok=True)
os.makedirs("raas-lanes", exist_ok=True)
for map_name in os.listdir(map_dir):
    if not os.path.isdir(f"{map_dir}/{map_name}") \
            or "EntryMap" in map_name \
            or "Forest" in map_name \
            or "Jensens_Range" in map_name \
            or "Tutorial" in map_name \
            or "Fallujah" in map_name:
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
                    bounds.append(struct.unpack("<fff", f.read(12)))

        with open(f"raas-lanes/{layer}.json", "w") as f:
            json.dump({
                "bounds": bounds,
                "lane_graph": lane_graph,
            }, f, sort_keys=True, indent=4)
