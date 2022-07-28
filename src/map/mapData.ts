import { CapturePoint } from "./capturePoint";
import { Cluster } from "./cluster";
import { Lane } from "./lane";
import { Queue } from "queue-typescript";
import * as cluster from "cluster";

class MapData {
  public capturePoints: Set<CapturePoint> = new Set();
  public clusters: Set<Cluster> = new Set();
  public mains: Set<CapturePoint> = new Set();
  public ownMain: CapturePoint | null = null;
  public lanes: Set<Lane> = new Set();

  public enemyMain(): CapturePoint | null {
    if (this.mains.size !== 2) return null;

    const mains = Array.from(this.mains);
    return this.ownMain === mains[0] ? mains[1] : mains[0];
  }

  public refreshGraphDirection() {
    // the two mains form a source-sink graph
    // (= one main has only outgoing edges,
    // the other main has only incoming edges)
    // to make calculations easier, we make sure that our ownMain is always the
    // source by flipping the edges if necessary
    if (this.ownMain === null) return;

    const mainCluster = Array.from(this.ownMain.clusters)[0];

    if (mainCluster.edges.size > 0) return; // already correct

    // flip all edges
    this.clusters.forEach((c) => {
      const tmp = c.edges;
      c.edges = c.reverseEdges;
      c.reverseEdges = tmp;
    });
  }

  public refreshLaneProbabilities() {
    // if we haven't chosen a main yet, just default all lanes being impossible
    if (this.ownMain === null) {
      this.lanes.forEach((lane) => {
        lane.probability = 0;
      });
      return;
    }

    /*
    for each lane, we have to calculate the probability of being on that lane
    *given* the current confirmation line, formally
    P[ lane | confirmation line ]

    The easiest way to compute this is to reverse this probability with
    Bayes' theorem:
    P[ confirmation line | lane ] * P[ lane ] / P[ confirmation line ]

    Fortunately, P[ lane ] and P[ confirmation line ] are the same for all
    lanes, which means that when comparing lane probabilities, those two factors
    would cancel out anyway, which is why we can ignore them.
    That means that for each lane, we only have to compute
    P[ confirmation line | lane ]
    ("how likely is it to reach this confirmation line on the given lane?")
    and then normalize the values so that they sum up to 1.

    Note that a CP can appear in multiple clusters, even within the same lane.
    Main CPs, however, are always in exactly one cluster.
    */
    const pConfirmationLinePerLane: Map<Lane, number> = new Map();
    let totalPConfirmationLine = 0;
    this.lanes.forEach((lane) => {
      // use DFS to go through all possible cluster combinations that are able
      // to produce the confirmation line
      const pConfirmationLineOnThisLane = this.calcPConLine(
        lane,
        Array.from(this.ownMain!.clusters)[0],
        this.ownMain!
      );

      pConfirmationLinePerLane.set(lane, pConfirmationLineOnThisLane);
      totalPConfirmationLine += pConfirmationLineOnThisLane;
    });

    this.lanes.forEach((lane) => {
      lane.probability =
        pConfirmationLinePerLane.get(lane)! / totalPConfirmationLine;
    });
  }

  /**
   * Calculates the probability of encountering the rest of the confirmation
   * line on a given lane, given that the specified sourceCluster and sourceCp
   * are already reached.
   */
  private calcPConLine(
    lane: Lane,
    sourceCluster: Cluster,
    sourceCp: CapturePoint
  ): number {
    if (sourceCp.confirmedFollower === null) {
      // we're at the end of the confirmation line
      // at this point, it's 100% likely to encounter the confirmation line
      return 1;
    }

    // go over all neighbours and add up the chance of encountering the
    // confirmation line via them
    let pConLine = 0;
    const outEdges = sourceCluster.edges.get(lane)!;

    outEdges.forEach((targetCluster) => {
      if (!targetCluster.points.has(sourceCp.confirmedFollower!)) {
        // target cluster does not contain next confirmed CP,
        // ignore cluster
        return;
      }

      // p[ target cluster ]
      // * p[ correct CP in target cluster ]
      // * p[ target cluster encounters con line]
      pConLine +=
        (1 / outEdges.size) *
        (1 / targetCluster.points.size) *
        this.calcPConLine(lane, targetCluster, sourceCp.confirmedFollower!);
    });
    return pConLine;
  }

  public refreshLaneLengthsAndClusterDistances() {
    if (this.ownMain === null) return;

    // go from our main cluster to the enemy one via BFS
    // assume that
    // - there are always 2 mains
    // - the main clusters are always on all lanes
    if (this.mains.size !== 2) {
      throw "amount of mains is not 2";
    }

    const [mainA, mainB] = Array.from(this.mains);
    let startMain = this.ownMain;
    let endMain = mainA;
    if (this.ownMain === mainA) {
      endMain = mainB;
    }

    let startCluster = Array.from(startMain.clusters)[0];
    let endCluster = Array.from(endMain.clusters)[0];

    this.lanes.forEach((lane) => {
      const visited: Set<Cluster> = new Set();
      const queue: Queue<Cluster | null> = new Queue();
      queue.enqueue(startCluster);
      queue.enqueue(null); // depth separator
      visited.add(startCluster);

      let depth = 0;

      while (queue.length > 0) {
        const cluster = queue.dequeue();

        if (cluster === null) {
          // we've exhausted the current depth
          depth += 1;
          queue.enqueue(null); // re-add null for next level
          if (queue.length === 1) break; // end of BFS
          continue;
        }

        // remember cluster depth
        cluster.distanceToOwnMain.set(lane, depth);

        // if we're at the enemy main, update lane length but don't
        // go backwards to find other neighbours
        // (if we did, we could come across unvisited clusters prematurely)
        if (cluster === endCluster) {
          lane.length = depth - 1;
          continue;
        }

        // enqueue all unvisited neighbour clusters
        cluster.edges.get(lane)!.forEach((nbCluster) => {
          if (!visited.has(nbCluster)) {
            visited.add(nbCluster);
            queue.enqueue(nbCluster);
          }
        });
      }
    });
  }

  public resetConfirmationLine() {
    this.capturePoints.forEach((cp) => {
      cp.confirmedFollower = null;
    });
  }
}

export const mapData: MapData = new MapData();
