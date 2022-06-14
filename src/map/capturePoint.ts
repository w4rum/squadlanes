import { Cluster } from "./cluster";
import { position } from "./position";

export class CapturePoint {
  public readonly name: string;
  public readonly displayName: string;
  public readonly pos: position;
  public clusters: Set<Cluster>;
  public confirmedFollower: CapturePoint | null;

  constructor(name: string, displayName: string, pos: position) {
    this.name = name;
    this.displayName = displayName;
    this.pos = pos;
    this.clusters = new Set();
    this.confirmedFollower = null;
  }

  equal(cpOther: CapturePoint): boolean {
    // consider two points equal if they are
    // very close and have the same displayName
    // TODO: shouldn't sdkName be used here?
    let distance = Math.sqrt(
      Math.pow(this.pos[0] - cpOther.pos[0], 2) +
        Math.pow(this.pos[1] - cpOther.pos[1], 2)
    );

    if (distance < 1000.0) {
      if (this.displayName !== cpOther.displayName) {
        console.warn(
          `Same position but different display name: ` +
            `${this.name}/${this.displayName} vs. ${cpOther.name}/${cpOther.displayName}`
        );
      }
      return true;
    }
    return false;
  }
}
