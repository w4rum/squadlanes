import { CapturePoint } from "./capturePoint";
import { redraw } from "./rendering";
import { mapData } from "./mapData";

export function handleConfirmationClick(cp: CapturePoint) {
  // if a main base was clicked, switch main base and reset
  if (mapData.mains.has(cp)) {
    mapData.ownMain = cp;
    mapData.resetConfirmationLine();
    mapData.refreshLaneLengthsAndClusterDistances();
    mapData.refreshLaneProbabilities();
    redraw();
    return;
  }

  // go to last point on confirmation line
  let curCp = mapData.ownMain!;
  let prevCp = null;
  while (curCp.confirmedFollower !== null) {
    prevCp = curCp;
    curCp = curCp.confirmedFollower;
  }

  // if clicked point is the last one of the confirmation line,
  // unconfirm point
  if (cp === curCp) {
    prevCp!.confirmedFollower = null;
    mapData.refreshLaneProbabilities();
    redraw();
    return;
  }

  // if clicked point is reachable
  // - with one hop
  // - on a possible lane
  // - towards the enemy main
  // then confirm point
  let reachable = false;
  curCp.clusters.forEach((sourceCluster) => {
    mapData.lanes.forEach((lane) => {
      // check if lane is impossible
      if (lane.probability === 0) return;

      // check if sourceCluster is on lane
      let edgeSet = sourceCluster.edges.get(lane);
      if (edgeSet === undefined) return;

      // check if CP is in any reachable targetCluster
      edgeSet.forEach((targetCluster) => {
        if (targetCluster.points.has(cp)) reachable = true;
      });
    });
  });

  if (reachable) {
    curCp.confirmedFollower = cp;
    mapData.refreshLaneProbabilities();
    redraw();
    return;
  }

  // ignore click
}
