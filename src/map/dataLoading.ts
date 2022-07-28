import { Cluster } from "./cluster";
import { CapturePoint } from "./capturePoint";
import { mapData } from "./mapData";
import { raasData } from "./raasData";
import { redraw, resetMap } from "./rendering";
import { Lane } from "./lane";
import Vue from "vue";

export function changeLayer(mapName: string, layerName: string) {
  // delete all existing map data
  mapData.capturePoints = new Set();
  mapData.clusters = new Set();
  mapData.mains = new Set();
  mapData.lanes = new Set();
  mapData.ownMain = null;

  // temporary look-up map only needed during extraction
  const clustersByName: Map<string, Cluster> = new Map();

  const layerData = raasData[mapName][layerName];

  // note which clusters appear on which lane, we need this to establish CP->Cluster relationship per-lane
  const clusters_on_lane = new Map();
  for (const laneName in layerData.lanes) {
    const links = layerData.lanes[laneName];
    const lane = new Lane(laneName);
    clusters_on_lane.set(lane, new Set());
    links.forEach((link) => {
      clusters_on_lane.get(lane).add(link["a"]);
      clusters_on_lane.get(lane).add(link["b"]);
    });

    // make Vue observable so that the percentages change
    mapData.lanes.add(Vue.observable(lane));
  }

  // extract clusters and capture points from YAML data
  for (const clusterName in layerData.clusters) {
    const cluster = new Cluster(clusterName);
    mapData.clusters.add(cluster);
    clustersByName.set(clusterName, cluster);

    layerData.clusters[clusterName].forEach((cpRaw) => {
      // create point, we'll detect duplicates in the next step
      let cp = new CapturePoint(cpRaw.sdk_name, cpRaw.display_name, [
        cpRaw.y,
        cpRaw.x,
      ]);

      // if there is an equal, just use it instead of the current CP, discard current CP
      mapData.capturePoints.forEach((cpOther) => {
        if (cp.equal(cpOther)) {
          cp = cpOther;
        }
      });

      // add CP to CP-set
      // (note that for duplicates, this does nothing)
      mapData.capturePoints.add(cp);

      // associate CP with cluster (will create backwards association as well)
      cluster.addPoint(cp);
    });
  }

  // extract cluster links for each lane
  mapData.lanes.forEach((lane) => {
    layerData.lanes[lane.name].forEach((link) => {
      const clusterA = clustersByName.get(link.a)!;
      const clusterB = clustersByName.get(link.b)!;

      // add directed edge
      clusterA.addEdgeTo(clusterB, lane);
    });
  });

  // extract main CPs by matching CP names
  mapData.capturePoints.forEach((cp) => {
    if (layerData.mains.indexOf(cp.name) !== -1) {
      mapData.mains.add(cp);
    }
  });

  // pre-compute lane lengths and cluster distances to increase performance
  mapData.refreshLaneLengthsAndClusterDistances();
  mapData.refreshLaneProbabilities();

  // trigger map gui reload
  resetMap(layerData);
  redraw();
}
