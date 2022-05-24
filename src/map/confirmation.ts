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
    return;
  }
  // TODO
  console.log(`Clicked on ${cp.displayName}`);
  mapData.refreshLaneProbabilities();
  redraw();
}
