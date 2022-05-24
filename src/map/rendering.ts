import {
  Browser,
  CircleMarker,
  circleMarker,
  CRS,
  DomEvent,
  DomUtil,
  extend,
  Map as LeafletMap,
  map as leafletMap,
  Polyline,
  polyline,
  TileLayer,
  Transformation,
} from "leaflet";
// @ts-ignore
import mapTiles from "../assets/map-tiles/**/**/**.png";
import { CapturePoint } from "./capturePoint";
import { mapData } from "./mapData";
import { handleConfirmationClick } from "./confirmation";
import { Lane } from "./lane";
import { Queue } from "queue-typescript";
import { LayerData } from "./raasData";

const CLR_CONFIRMED = "rgb(0,255,13)";
const CLR_ACTIVE = "rgb(176,255,148)";
const CLR_MID_POINT = "rgb(186,0,255)";
const CLR_DEF_POINT = "rgb(0,55,255)";
const CLR_DEF_OTHER = [
  "rgb(47,182,255)",
  "rgb(145,245,220)",
  "rgb(161,250,186)",
];
const CLR_OFF_POINT = "rgb(255,0,0)";
const CLR_OFF_OTHER = [
  "rgb(255,162,92)",
  "rgb(252,227,108)",
  "rgb(253,246,203)",
];
const CLR_IMPOSSIBLE = "rgb(145,145,145)";
const CLR_MAIN_BASE = "rgb(0,0,0)";

const CLR_PRIORITY = {
  // priority 99 means that caps aren't eligible for other colours anyway
  CONFIRMED: 99,
  IMPOSSIBLE: 99,
  MAIN_BASE: 99,
  ACTIVE: 8,
  MID_POINT: 6,
  DEF_POINT: 4,
  OFF_POINT: 2,
  OTHER: 0,
};

class CPRenderInfo {
  public color: string;
  public visible: boolean;
  public centerNumber: string;
  public laneLabels: string[];

  private priority: any;

  constructor() {
    this.color = CLR_IMPOSSIBLE;
    this.visible = false;
    this.centerNumber = "&nbsp";
    this.laneLabels = [];
    this.priority = Number.MIN_SAFE_INTEGER;
  }

  upgrade(
    color: string,
    depth: number | null,
    lane: Lane | null,
    priority: number
  ) {
    // only add lane tag if CP is not on the confirmation line
    if (depth !== null && lane !== null) {
      this.laneLabels.push(`${depth}${lane.name}`);
      this.centerNumber = depth.toString();
    }

    this.visible = true;
    if (priority > this.priority) {
      this.priority = priority;
      this.color = color;
    }
  }
}

export let map: LeafletMap | null = null;

let capturePointByCircleMarker: Map<CircleMarker, CapturePoint> = new Map();
let circleMarkerByCapturePoint: Map<CapturePoint, CircleMarker> = new Map();

let renderInfos: Map<CircleMarker, CPRenderInfo> = new Map();

let confirmationLines: Set<Polyline> = new Set();

const dummyLane = new Lane("DUMMY");

export function resetMap(layerData: LayerData) {
  // remove existing map data
  if (map !== null) {
    map.remove();
    capturePointByCircleMarker = new Map();
    circleMarkerByCapturePoint = new Map();
  }

  const bounds = layerData["background"]["corners"];

  const baseBounds = [
    [bounds[0]["y"], bounds[0]["x"]],
    [bounds[1]["y"], bounds[1]["x"]],
  ];
  const width = Math.abs(bounds[0]["x"] - bounds[1]["x"]);
  const height = Math.abs(bounds[0]["y"] - bounds[1]["y"]);

  const up_left_x = Math.min(bounds[0]["x"], bounds[1]["x"]);
  const up_left_y = Math.min(bounds[0]["y"], bounds[1]["y"]);

  const zoomOffset = 0;
  let tileSize = 256;

  const x_stretch = tileSize / width;
  const y_stretch = tileSize / height;

  const crs = extend({}, CRS.Simple, {
    // Move origin to upper left corner of map
    // need to do this because TileLayer always puts the left-upper corner on the origin
    transformation: new Transformation(
      x_stretch,
      -up_left_x * x_stretch,
      y_stretch,
      -up_left_y * y_stretch
    ),
  });

  map = leafletMap("map", {
    crs: crs,
    minZoom: 0,
    maxZoom: 6,
    zoomSnap: 0.1,
    zoomDelta: 1.0,
    dragging: true,
    boxZoom: true,
    scrollWheelZoom: true,
    touchZoom: true,
    zoomControl: true,
    doubleClickZoom: false,
    attributionControl: false,
  });

  // @ts-ignore
  map.fitBounds(baseBounds);
  map.createPane("cp");
  map.getPane("cp")!.style.zIndex = "20";
  map.createPane("cpTooltip");
  map.getPane("cpTooltip")!.style.zIndex = "30";
  map.createPane("confirmationLines");
  map.getPane("confirmationLines")!.style.zIndex = "10";
  map.createPane("background");
  map.getPane("background")!.style.zIndex = "0";

  // override tile URL template function to support loading our bundled tiles instead
  const TileLayerBundledTiles = TileLayer.extend({
    getTileUrl(coords: { x: number; y: number; z: number }) {
      // we use the first constructor parameter (usually the URL template) as the map name
      const map = mapTiles[this._url];
      if (!map) return null;
      const zoomLevel = map[coords.z];
      if (!zoomLevel) return null;
      const column = zoomLevel[coords.x];
      if (!column) return null;
      const cell = column[coords.y];
      if (!cell) return null;

      return cell;
    },
  });

  let map_image_name = layerData["background"]["minimap_filename"];
  // @ts-ignore
  new TileLayerBundledTiles(map_image_name, {
    tms: false,
    maxNativeZoom: 4,
    zoomOffset: zoomOffset,
    // scale tiles to match minimap width and height
    tileSize: tileSize,
    pane: "background",
    bounds: baseBounds,
  }).addTo(map);

  // create markers for capture points
  mapData.capturePoints.forEach((cp) => {
    const cm = circleMarker(cp.pos, {
      radius: 20,
      pane: "cp",
    });

    // remember mapping between CircleMarker and CapturePoint
    circleMarkerByCapturePoint.set(cp, cm);
    capturePointByCircleMarker.set(cm, cp);

    cm.addTo(map!);

    // clicks are used to confirm points
    cm.on("click", (ev) => {
      handleConfirmationClick(cp);
    });

    // during mouseover, the font color and size changes
    // (we add a CSS class and re-open the tooltip)
    cm.on("mouseover", (ev) => {
      const tt = cm.getTooltip();
      if (tt !== undefined) {
        // this will probably break at some point
        // @ts-ignore
        DomUtil.addClass(tt._container, "mouseover");
      }
      // re-open tooltip to make sure text is still centered
      cm.closeTooltip();
      cm.openTooltip();
    });
    cm.on("mouseout", (ev) => {
      const tt = cm.getTooltip();
      if (tt !== undefined) {
        // @ts-ignore
        L.DomUtil.removeClass(tt._container, "mouseover");
      }
      cm.closeTooltip();
      cm.openTooltip();
    });
  });

  // make sure the leaflet map rescales properly when the window is resized
  const mapDiv = document.getElementById("map")!;
  new ResizeObserver(() => {
    map!.invalidateSize();
    // @ts-ignore
    map!.fitBounds(baseBounds, {
      animate: false,
    });
  }).observe(mapDiv);

  // Debug
  if (window.location.hostname.startsWith("dev.")) {
    map.addEventListener("mousedown", function (ev) {
      // @ts-ignore
      const lat = ev.latlng.lat;
      // @ts-ignore
      const lng = ev.latlng.lng;
    });
  }
}

export function redraw() {
  // remove all existing on-click handlers
  // (to remove on-click functionality of invisible CPs)
  circleMarkerByCapturePoint.forEach((cm) => {
    cm.off("click");
  });

  // set default (hidden) rendering setting for all CPs
  circleMarkerByCapturePoint.forEach((cm) => {
    renderInfos.set(cm, new CPRenderInfo());
  });

  // upgrade CPRenderInfo as far as possible for every point
  if (mapData.ownMain !== null) {
    determineCPPossibilities();
  } else {
    // if no main base is selected, use special treatment to show both
    mapData.mains.forEach((mainCp) => {
      renderInfos
        .get(circleMarkerByCapturePoint.get(mainCp)!)!
        .upgrade(CLR_MAIN_BASE, 0, dummyLane, CLR_PRIORITY.MAIN_BASE);
    });
  }

  // Update all circle markers
  renderInfos.forEach((rI, cm) => {
    const cp = capturePointByCircleMarker.get(cm)!;
    // remove hidden CPs and re-add previously hidden but not visible CPs
    if (!rI.visible) {
      // hide circlemarker
      cm.remove();
      return;
    } else if (!map!.hasLayer(cm)) {
      cm.addTo(map!);
    }

    // delete old tooltip
    cm.closeTooltip().unbindTooltip();

    // concat lane labels (unless main hasn't been chosen yet)
    let laneTooltip =
      mapData.ownMain !== null ? rI.laneLabels.join(",") : "&nbsp";

    // create new tooltip
    cm.bindTooltip(
      `<div class="cpTooltipName">${cp.displayName}</div>` +
        `<div class="cpTooltipDepth">${rI.centerNumber}</div>` +
        `<div class="cpTooltipLanes">${laneTooltip}</div>`,
      {
        permanent: true,
        direction: "top",
        opacity: 1.0,
        className: "cpTooltip",
        pane: "cpTooltip",
        offset: [0, 50],
      }
    ).openTooltip();

    // set correct color
    cm.setStyle({
      color: rI.color,
      opacity: 1.0,
      interactive: true,
      fill: true,
    });

    cm.redraw();
  });

  // draw confirmation line
  // first, remove line
  confirmationLines.forEach((line) => {
    line.remove();
  });

  // go through confirmation line and add a line segment between all points
  let cp = mapData.ownMain;
  let prev: CapturePoint | null = null;
  while (cp !== null) {
    if (prev !== null) {
      // only connect neighbouring CPs when both are confirmed or mandatory
      const line = polyline([prev.pos, cp.pos], {
        color: "rgb(102,202,193)",
        pane: "confirmationLines",
      }).addTo(map!);
      confirmationLines.add(line);
    }
    prev = cp;
    cp = cp.confirmedFollower;
  }
}

function determineCPPossibilities() {
  // show all points on the confirmation line
  let curConfirmedPoint = mapData.ownMain;
  let endOfConfirmationLine: CapturePoint;
  let depth = 0;
  while (curConfirmedPoint !== null) {
    endOfConfirmationLine = curConfirmedPoint;

    renderInfos
      .get(circleMarkerByCapturePoint.get(curConfirmedPoint)!)!
      .upgrade(CLR_CONFIRMED, null, null, CLR_PRIORITY.CONFIRMED);

    curConfirmedPoint = curConfirmedPoint.confirmedFollower;
    depth += 1;
  }
  const confirmationDepth = depth;

  // use BFS to show all the points beyond the end of the confirmation line
  // ignore impossible lanes
  const possibleLanes: Set<Lane> = new Set();
  mapData.lanes.forEach((lane) => {
    if (lane.probability > 0) {
      possibleLanes.add(lane);
    }
  });

  let queue: Queue<CapturePoint | null> = new Queue();
  queue.enqueue(endOfConfirmationLine!);
  // use null as a depth-separator
  queue.enqueue(null);

  // note that we don't have a "visited" set
  // this is acceptable because
  // - we only explore in one direction (towards enemy main)
  // - the impact of unnecessarily checking clusters multiple times is negligible

  while (queue.length > 0) {
    let cp = queue.dequeue();

    // check if we've exhausted the current depth
    if (cp === null) {
      // if there are no remaining capture points, stop
      if (queue.length === 0) {
        break;
      } else {
        depth += 1;
        // insert a new depth-separator
        queue.enqueue(null);
        continue;
      }
    }

    // go through possible neighbours of this CP
    // (first, go through all possible clusters for this CP)
    cp.clusters.forEach((cluster) => {
      // go through all possible lanes and check if cluster appears on that lane
      possibleLanes.forEach((lane) => {
        // go through all neighbouring clusters on this lane
        // (will be undefined if cluster is not present on this lane)
        const nbClusters = cluster.edges.get(lane);

        // if the cluster isn't present on this lane, skip lane
        if (nbClusters === undefined) return;

        nbClusters.forEach((nbCluster) => {
          // only look at clusters that are closer to the enemy main
          if (nbCluster.distanceToOwnMain.get(lane)! <= depth) return;

          // go through all CPs of neighbouring cluster
          nbCluster.points.forEach((nbCp) => {
            // add color possibility
            const { color, priority } = getColorAndPriorityForLaneDepth(
              lane,
              depth,
              confirmationDepth
            );
            renderInfos
              .get(circleMarkerByCapturePoint.get(nbCp)!)!
              .upgrade(color, depth, lane, priority);
            // check that CPs neighbours next
            queue.enqueue(nbCp);
          });
        });
      });
    });
  }
}

function getColorAndPriorityForLaneDepth(
  lane: Lane,
  depth: number,
  confirmationDepth: number
): { color: string; priority: number } {
  const defDepth = Math.floor(lane.length / 2);
  let offDepth: number;
  let midDepth: number;

  // on an even-length lane, there is no midpoint
  if (lane.length % 2 === 0) {
    midDepth = -1;
    offDepth = defDepth + 1;
  } else {
    midDepth = defDepth + 1;
    offDepth = defDepth + 2;
  }

  // enemy main (no need to check own main because it's always a confirmed CP)
  if (depth === lane.length) {
    return { color: CLR_MAIN_BASE, priority: CLR_PRIORITY.MAIN_BASE };
  }

  // the following are checked in order of decreasing priority
  // 1. possible next point
  // 2. mid points
  // 3. frontline defense
  // 4. frontline offense
  // 5. backline defense
  // 6. backline offense
  if (depth === confirmationDepth + 1) {
    return { color: CLR_ACTIVE, priority: CLR_PRIORITY.ACTIVE };
  }

  if (depth === midDepth) {
    return { color: CLR_MID_POINT, priority: CLR_PRIORITY.MID_POINT };
  }

  if (depth === defDepth) {
    return { color: CLR_DEF_POINT, priority: CLR_PRIORITY.DEF_POINT };
  }

  if (depth === offDepth) {
    return { color: CLR_OFF_POINT, priority: CLR_PRIORITY.OFF_POINT };
  }

  if (depth < defDepth) {
    return {
      color: CLR_DEF_OTHER[defDepth - depth - 1],
      priority: CLR_PRIORITY.OTHER,
    };
  }

  if (depth > offDepth) {
    return {
      color: CLR_OFF_OTHER[depth - offDepth - 1],
      priority: CLR_PRIORITY.OTHER,
    };
  }

  throw `this shouldn't happen`;
}
