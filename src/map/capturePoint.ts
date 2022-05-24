import { Cluster } from "./cluster";
import { position } from "./position";
import { DomUtil } from "leaflet";
import disableImageDrag = DomUtil.disableImageDrag;

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

  onClick() {
    // ignore clicks on own main
    if (this === ownMain) {
      return;
    } // clicks on another main will trigger a reset
    else if (this === cpBluforMain || this === cpOpforMain) {
      ownMain = this;
      resetConfirmations();
      return;
    }

    // iterate through confirmation line
    let prev = null;
    let cur = ownMain;
    while (cur.confirmedFollower !== null) {
      // if this point is in the middle of the confirmation line, ignore click
      if (cur === this) {
        return;
      }

      prev = cur;
      cur = cur.confirmedFollower;
    }
    // if this point is the end of the confirmation line, remove it from the confirmation line
    if (cur === this) {
      prev.confirmedFollower = null;
      redraw();
      return;
    }
    // check if this point lies right after the confirmation line
    const forward = ownMain !== cpOpforMain;
    cur.clusters.forEach((cluster, lane) => {
      const thisCluster = this.clusters.get(lane);
      if (cluster.edges.get(lane).has(thisCluster)) {
        // add point to confirmation line
        cur.confirmedFollower = this;
        redraw();
        return;
      }
    });

    // otherwise, point lies behind confirmation line and is not the next point
    // => ignore click
    return;
  }
}
