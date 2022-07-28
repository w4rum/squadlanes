import { Lane } from "./lane";
import { CapturePoint } from "./capturePoint";

export class Cluster {
  public readonly name: string;
  public edges: Map<Lane, Set<Cluster>>;
  public reverseEdges: Map<Lane, Set<Cluster>>;
  public points: Set<CapturePoint>;
  public distanceToOwnMain: Map<Lane, number>;

  constructor(name: string) {
    this.name = name;
    this.edges = new Map();
    this.reverseEdges = new Map();
    this.points = new Set();
    this.distanceToOwnMain = new Map();
  }

  addEdgeTo(target: Cluster, lane: Lane) {
    Cluster.addEdgeToEdgeSet(this.edges, target, lane);
    Cluster.addEdgeToEdgeSet(target.reverseEdges, this, lane);
  }

  private static addEdgeToEdgeSet(
    edgeSet: Map<Lane, Set<Cluster>>,
    target: Cluster,
    lane: Lane
  ) {
    if (!edgeSet.has(lane)) {
      edgeSet.set(lane, new Set());
    }
    edgeSet.get(lane)!.add(target);
  }

  addPoint(point: CapturePoint) {
    this.points.add(point);
    point.clusters.add(this);
  }
}
