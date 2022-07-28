import { Cluster } from "./cluster";
import { mapData } from "./mapData";
import { Lane } from "./lane";
import { CapturePoint } from "./capturePoint";

export function getAllPossibleConfirmedPaths(lane: Lane): Cluster[][] {
  const startCp = mapData.ownMain!;
  // mains only have one cluster (inb4 OWI changes that)
  const startCluster = Array.from(startCp.clusters)[0];

  return getPossibleConfirmedPathsFromHere(startCp, startCluster, [], lane);
}

function getPossibleConfirmedPathsFromHere(
  cp: CapturePoint,
  cluster: Cluster,
  path: Cluster[],
  lane: Lane
): Cluster[][] {
  // add ourselves to the path
  path.push(cluster);

  // if we're at the end, just return the path prefix
  // as the only possible full path
  if (cp.confirmedFollower === null) {
    return [path];
  }

  const targetCp = cp.confirmedFollower;
  let possiblePaths: Cluster[][] = [];

  cluster.edges.get(lane)!.forEach((nbCluster) => {
    // ignore neighbours w/o the target CP
    if (!nbCluster.points.has(targetCp)) return;

    // ignore clusters that we've already traversed
    if (path.indexOf(nbCluster) !== -1) return;

    // clone the path to avoid children interfering with each other
    const pathClone: Cluster[] = [...path];

    // merge the returned possible paths onto the existing ones
    possiblePaths = [
      ...possiblePaths,
      ...getPossibleConfirmedPathsFromHere(
        targetCp,
        nbCluster,
        pathClone,
        lane
      ),
    ];
  });

  return possiblePaths;
}

type Depth = {
  depth: number;
  path_length: number;
};

export function getAllPossibleDepths(
  confirmedPath: Cluster[],
  lane: Lane
): Map<Cluster, Set<Depth>> {
  // first get all possible second halves of the path
  const enemyMainCluster = Array.from(mapData.enemyMain()!.clusters)[0];

  const possiblePaths: Cluster[][] = getPossibleDepthsFromHere(
    enemyMainCluster,
    confirmedPath,
    [],
    lane
  );

  // now traverse these paths and, for each cluster,
  // remember all possible depths
  const possibleDepths: Map<Cluster, Set<Depth>> = new Map();

  possiblePaths.forEach((path) => {
    // not including main bases
    const fullPathLength = path.length - 1 + confirmedPath.length - 1;

    for (let i = 0; i < path.length - 1; i++) {
      const cluster = path[i + 1];
      let depthSet = possibleDepths.get(cluster);

      if (depthSet === undefined) {
        depthSet = new Set();
        possibleDepths.set(cluster, depthSet);
      }

      depthSet.add({ depth: fullPathLength - i, path_length: fullPathLength });
    }
  });

  return possibleDepths;
}

function getPossibleDepthsFromHere(
  cluster: Cluster,
  confirmedPath: Cluster[],
  path: Cluster[],
  lane: Lane
): Cluster[][] {
  // add ourselves to the path
  path.push(cluster);

  let possiblePaths: Cluster[][] = [];

  const targetCluster = confirmedPath[confirmedPath.length - 1];

  cluster.reverseEdges.get(lane)!.forEach((nbCluster) => {
    // ignore clusters that we've already traversed
    if (path.indexOf(nbCluster) !== -1) return;

    // if the next cluster is the target cluster,
    // then we are a possible end of the path
    if (nbCluster === targetCluster) {
      possiblePaths.push(path);
      return;
    }

    // ignore confirmed clusters that don't contain the target CP
    if (confirmedPath.indexOf(nbCluster) !== -1) return;

    const pathClone = [...path];
    possiblePaths = [
      ...possiblePaths,
      ...getPossibleDepthsFromHere(nbCluster, confirmedPath, pathClone, lane),
    ];
  });

  return possiblePaths;
}
