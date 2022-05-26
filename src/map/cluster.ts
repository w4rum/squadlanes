import { Lane } from "./lane";
import { CapturePoint } from "./capturePoint";

export class Cluster {
  public readonly name: string;
  public edges: Map<Lane, Set<Cluster>>;
  public points: Set<CapturePoint>;
  public distanceToOwnMain: Map<Lane, number>;

  constructor(name: string) {
    this.name = name;
    this.edges = new Map();
    this.points = new Set();
    this.distanceToOwnMain = new Map();
  }

  addEdgeTo(target: Cluster, lane: Lane) {
    if (!this.edges.has(lane)) {
      this.edges.set(lane, new Set());
    }
    this.edges.get(lane)!.add(target);
  }

  addPoint(point: CapturePoint) {
    this.points.add(point);
    point.clusters.add(this);
  }
}
