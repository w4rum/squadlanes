import { Cluster } from "./cluster";
import { position } from "./position";

export class CapturePoint {
  public readonly name: string;
  // sometimes we merge points with the same name because they are on the same
  // position and never appear together
  // to keep track of the display names, we store them as an array
  public displayName: string[];
  public readonly pos: position;
  public clusters: Set<Cluster>;
  public confirmedFollower: CapturePoint | null;

  constructor(name: string, displayName: string, pos: position) {
    this.name = name;
    this.displayName = [displayName];
    this.pos = pos;
    this.clusters = new Set();
    this.confirmedFollower = null;
  }

  equal(cpOther: CapturePoint): boolean {
    // consider two points equal if they are very close
    let distance = Math.sqrt(
      Math.pow(this.pos[0] - cpOther.pos[0], 2) +
        Math.pow(this.pos[1] - cpOther.pos[1], 2)
    );

    return distance < 1500.0;
  }
}
