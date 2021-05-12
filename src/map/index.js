import YAML from "yaml-js";
import L from "leaflet";
import rassDataYaml from "../assets/raas-data.yaml";
import {BehaviorSubject} from "rxjs";
import {Queue} from "./queue";

import mapTiles from '../assets/map-tiles/**/**/**.png'

let capturePoints = null;
let clusters = null;
let cpBluforMain = null;
let cpOpforMain = null;
let cpLines = null;
let map = null;
let ownMain = null;
let allLanes = null;
let laneLengths = null;
export let raasData = rassDataYaml;
const raasDataSubscriber = new Set();
export const lanePercentages = new BehaviorSubject({west: 33, east: 33, center: 33});

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
}

class Cluster {
    constructor() {
        this.outgoingEdges = new Map();
        this.incomingEdges = new Map();
        this.points = new Set();
    }

    addEdgeTo(target, lane) {
        this._addEdgeTo(target, lane, true);
    }

    _addEdgeTo(target, lane, outgoing) {
        const edgeSet = outgoing ? this.outgoingEdges : this.incomingEdges;
        if (!edgeSet.has(lane)) {
            edgeSet.set(lane, new Set());
        }
        edgeSet.get(lane).add(target);

        // add backwards edges
        if (outgoing) {
            target._addEdgeTo(this, lane, false);
        }
    }

    addPoint(point, lane) {
        this.points.add(point);
        point.clusters.set(lane, this);
    }
}

class CapturePoint {
    constructor(name, displayName, pos) {
        this.name = name;
        this.displayName = displayName;
        this.pos = pos;
        this.circleMarker = null;
        this.clusters = new Map();
        this.confirmedFollower = null;
    }

    equal(cpOther) {
        if (pointDistance(this.pos, cpOther.pos) < 1000.0) {
            if (this.displayName !== cpOther.displayName) {
                console.warn(`Same position but different display name: ` +
                    `${this.name}/${this.displayName} vs. ${cpOther.name}/${cpOther.displayName}`);
            }
            return true;
        }
        return false;
    }

    onClick() {
        // ignore clicks on own main
        if (this === ownMain) {
            return;
        } else // clicks on another main will trigger a reset
        if (this === cpBluforMain || this === cpOpforMain) {
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
            const edgeSet = forward ? cluster.outgoingEdges : cluster.incomingEdges;
            const thisCluster = this.clusters.get(lane);
            if (edgeSet.get(lane).has(thisCluster)) {
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

class CPRenderInfo {
    constructor() {
        this.color = CLR_IMPOSSIBLE;
        this.visible = false;
        this.centerNumber = "&nbsp";
        this.laneLabels = [];
        this.priority = Number.MIN_SAFE_INTEGER;
    }

    addInfoPossibility(color, depth, lane, priority) {
        this.laneLabels.push(`${depth}${lane[0]}`);
        this.visible = true;
        if (priority > this.priority) {
            this.priority = priority;
            this.color = color;
            this.centerNumber = depth;
        }
    }
}

function resetConfirmations() {
    capturePoints.forEach(cp => {
        cp.confirmedFollower = null;
    });
    redraw();
}

function pointDistance(posA, posB) {
    return Math.sqrt(
        Math.pow(posA[0] - posB[0], 2)
        + Math.pow(posA[1] - posB[1], 2)
    )
}

function union(setA, setB) {
    return new Set([...setA, ...setB]);
}

function intersection(setA, setB) {
    return new Set([...setA].filter(x => setB.has(x)));
}

function difference(setA, setB) {
    return new Set([...setA].filter(x => !setB.has(x)));
}

function lastConfirmedPoint() {
    let cur = ownMain;
    while (cur.follower !== null) {
        cur = cur.follower;
    }
    return cur;
}

function redraw() {
    // remove all existing on-click handlers
    capturePoints.forEach(cp => {
        cp.circleMarker.off('click');
    })

    // set default (hidden) rendering setting for all CPs
    const renderInfos = new Map();
    capturePoints.forEach(cp => {
        renderInfos.set(cp, new CPRenderInfo());
    });

    // special treatment for main bases if none are selected
    if (ownMain !== cpBluforMain && ownMain !== cpOpforMain) {
        renderInfos.get(cpBluforMain).addInfoPossibility(CLR_MAIN_BASE, 0, "DUMMY", CLR_PRIORITY.MAIN_BASE);
        renderInfos.get(cpOpforMain).addInfoPossibility(CLR_MAIN_BASE, 0, "DUMMY", CLR_PRIORITY.MAIN_BASE);
    }

    const forward = ownMain !== cpOpforMain;
    const mainCp = ownMain;

    // go through confirmation line
    let possibleLanes = new Set(allLanes);
    let lastConfirmedPoint = null;
    let curConfirmedPoint = mainCp;
    let curDepth = 0;
    do {
        // check on which lanes the edge from last->cur can be taken
        let lanesWithCorrectEdge;
        if (lastConfirmedPoint === null) {
            // this is the first point, all lanes of this point are valid
            // note: we can't just use allLanes because the dummy mains don't have lanes
            lanesWithCorrectEdge = new Set(curConfirmedPoint.clusters.keys());
        } else {
            lanesWithCorrectEdge = new Set();
            for (const lane of curConfirmedPoint.clusters.keys()) {
                const lastCluster = lastConfirmedPoint.clusters.get(lane);
                if (!lastCluster) continue;

                const curCluster = curConfirmedPoint.clusters.get(lane);
                if (!curCluster) continue;

                const edgeSet = forward ? lastCluster.outgoingEdges : lastCluster.incomingEdges;
                if (edgeSet.get(lane).has(curCluster)) {
                    lanesWithCorrectEdge.add(lane);
                }
            }
        }
        // intersect possible lanes
        possibleLanes = intersection(possibleLanes, lanesWithCorrectEdge);
        // possibleLanes = intersection(possibleLanes, new Set());
        // mark selected CP as confirmed in all possible lanes
        possibleLanes.forEach(lane => {
            renderInfos.get(curConfirmedPoint).addInfoPossibility(CLR_CONFIRMED, curDepth, lane, CLR_PRIORITY.CONFIRMED);
        });
        curDepth += 1;
        lastConfirmedPoint = curConfirmedPoint;
        curConfirmedPoint = curConfirmedPoint.confirmedFollower;
    } while (curConfirmedPoint !== null);
    const postConfirmationDepth = curDepth;

    // Compute conditional probabilities
    let laneProb = computeLaneProbabilities(lastConfirmedPoint, possibleLanes);

    // traverse graph for each lane and collect render info
    allLanes.forEach(lane => {
        // ignore impossible lanes
        if (!possibleLanes.has(lane)) {
            return;
        }

        // BFS over entire graph to get lane labels and depth-dependent color
        const visited = new Set();
        const queue = new Queue();
        // start after last confirmed point
        const edgeSet = forward ?
            lastConfirmedPoint.clusters.get(lane).outgoingEdges
            : lastConfirmedPoint.clusters.get(lane).incomingEdges;
        edgeSet.get(lane).forEach(queue.enqueue);
        queue.enqueue(null); // add null as a depth separator
        curDepth = postConfirmationDepth;

        // for the first level after the end of the confirmation line,
        // apply the active color and set the on-click handler
        let levelAfterConfirmation = true;

        while (!queue.isEmpty()) {
            const cur = queue.dequeue();
            if (cur === null) {
                curDepth += 1;
                levelAfterConfirmation = false;
                queue.enqueue(null); // re-add null for next level
                if (queue.getLength() === 1) break; // end of BFS
                continue;
            }

            // update info for all CPs in cluster
            const defDepth = Math.floor(laneLengths.get(lane) / 2);
            let offDepth = defDepth + 1;
            let midDepth = null;
            if (laneLengths.get(lane) % 2 === 1) {
                midDepth = offDepth;
                offDepth += 1;
            }
            cur.points.forEach(cp => {
                const rI = renderInfos.get(cp);
                if (levelAfterConfirmation) {
                    rI.addInfoPossibility(CLR_ACTIVE, curDepth, lane, CLR_PRIORITY.ACTIVE);
                    return;
                }
                if (cp === cpOpforMain || cp === cpBluforMain) {
                    rI.addInfoPossibility(CLR_MAIN_BASE, curDepth, lane, CLR_PRIORITY.MAIN_BASE);
                    return;
                }
                // get depths of layer to determine offense / defense / mid points
                // only check for mid-points on lanes with uneven capture points
                if (midDepth !== null && curDepth === midDepth) {
                    rI.addInfoPossibility(CLR_MID_POINT, curDepth, lane, CLR_PRIORITY.MID_POINT);
                    return;
                }
                if (curDepth === defDepth) {
                    rI.addInfoPossibility(CLR_DEF_POINT, curDepth, lane, CLR_PRIORITY.DEF_POINT);
                    return;
                }
                if (curDepth === offDepth) {
                    rI.addInfoPossibility(CLR_OFF_POINT, curDepth, lane, CLR_PRIORITY.OFF_POINT);
                    return;
                }
                if (curDepth < defDepth) {
                    const offset = defDepth - curDepth;
                    rI.addInfoPossibility(CLR_DEF_OTHER[offset - 1], curDepth, lane, CLR_PRIORITY.OTHER - offset);
                    return;
                }
                if (curDepth > offDepth) {
                    const offset = curDepth - offDepth;
                    rI.addInfoPossibility(CLR_OFF_OTHER[offset - 1], curDepth, lane, CLR_PRIORITY.OTHER - offset);
                    return;
                }
            });

            const edgeSet = forward ? cur.outgoingEdges : cur.incomingEdges;

            if (!edgeSet.has(lane)) {
                continue;
            }
            edgeSet.get(lane).forEach(nb => {
                if (!visited.has(nb)) {
                    visited.add(nb);
                    queue.enqueue(nb);
                }
            });
        }

    });

    capturePoints.forEach(cp => {
        // Update circle marker for all CPs
        const rI = renderInfos.get(cp);
        if (!rI.visible) {
            cp.circleMarker.remove();
            /*
            cp.circleMarker.setStyle({
                opacity: 0.0,
                interactive: false,
                fill: false,
            });
             */
            return;
        }
        if (!map.hasLayer(cp.circleMarker)) {
            cp.circleMarker.addTo(map);
        }
        cp.circleMarker.closeTooltip().unbindTooltip();

        const mainChosen = ownMain === cpBluforMain || ownMain === cpOpforMain;
        let laneTooltip = allLanes.size > 1 && mainChosen ? rI.laneLabels.join(",") : "&nbsp";
        cp.circleMarker.bindTooltip(
            `<div class="cpTooltipName">${cp.displayName}</div>` +
            `<div class="cpTooltipDepth">${rI.centerNumber}</div>` +
            `<div class="cpTooltipLanes">${laneTooltip}</div>`, {
                permanent: true,
                direction: 'top',
                opacity: 1.0,
                className: 'cpTooltip',
                pane: 'cpTooltip',
                offset: [0, 50],
            }).openTooltip();
        cp.circleMarker.setStyle({
            color: rI.color,
            opacity: 1.0,
            interactive: true,
            fill: true,
        });
        cp.circleMarker.on('click', ev => cp.onClick());
        cp.circleMarker.redraw();
    });

    const laneProbabilities = [...allLanes.values()].reduce((acc, lane) => {
        const prob = laneProb.get(lane);
        return {
            ...acc,
            [lane]: prob ? toPercent(laneProb.get(lane)) : 0
        }
    }, {});

    lanePercentages.next(laneProbabilities);

    // confirmation line
    cpLines.forEach(line => {
        line.remove();
    })
    let cur = mainCp;
    while (cur.confirmedFollower !== null) {
        // only connect neighbouring CPs when both are confirmed or mandatory
        const line = L.polyline([cur.pos, cur.confirmedFollower.pos], {
            color: "rgb(102,202,193)",
            pane: "cpLines",
        }).addTo(map);
        cpLines.add(line);
        cur = cur.confirmedFollower;
    }
    // also connect to enemy main if confirmation line includes mercy bleed
    possibleLanes.forEach(lane => {
        const cluster = cur.clusters.get(lane);
        const edgeSet = forward ? cluster.outgoingEdges : cluster.incomingEdges;
        const otherMain = forward ? cpOpforMain : cpBluforMain;
        if (edgeSet.get(lane).has(otherMain.clusters.get(lane))) {
            // TODO: deduplicate
            const line = L.polyline([cur.pos, otherMain.pos], {
                color: "rgb(102,202,193)",
                pane: "cpLines",
            }).addTo(map);
            cpLines.add(line);
        }
    })

}

function loadRaasDataFromString(yamlString) {
    raasData = YAML.parse(yamlString);
    changeMap("Narva", "RAAS v1");
    triggerRaasDataSubscribers();
}

function loadRaasData(path, callback) {
    YAML.load(path, rd => {
        raasData = rd;
        callback();
        triggerRaasDataSubscribers();
    });
}

function onRaasDataLoad(callback) {
    raasDataSubscriber.add(callback);
}

function triggerRaasDataSubscribers() {
    raasDataSubscriber.forEach(callback => {
        callback();
    });
}

export function changeMap(mapName, layerName) {
    // reset map data
    if (map !== null) {
        map.remove();
    }
    capturePoints = new Set();
    clusters = new Set();
    const clustersByName = new Map();
    cpBluforMain = null;
    cpOpforMain = null;
    cpLines = new Set();
    ownMain = null;
    allLanes = new Set();
    laneLengths = new Map();

    const layer_data = raasData[mapName][layerName];

    const bounds = layer_data["background"]["corners"]
    const raw_clusters = layer_data["clusters"]
    const laneGraph = layer_data["lanes"]

    const baseBounds = [[bounds[0]["y"], bounds[0]["x"]], [bounds[1]["y"], bounds[1]["x"]]];
    const width = Math.abs(bounds[0]["x"] - bounds[1]["x"]);
    const height = Math.abs(bounds[0]["y"] - bounds[1]["y"]);

    const up_left_x = Math.min(bounds[0]["x"], bounds[1]["x"]);
    const up_left_y = Math.min(bounds[0]["y"], bounds[1]["y"]);

    const zoomOffset = 0;
    let tileSize = 256;

    const x_stretch = tileSize / width;
    const y_stretch = tileSize / height;

    const crs = L.extend({}, L.CRS.Simple, {
        // Move origin to upper left corner of map
        // need to do this because TileLayer always puts the left-upper corner on the origin
        transformation: new L.Transformation(x_stretch, -up_left_x * x_stretch, y_stretch, -up_left_y * y_stretch),
    });

    map = L.map('map', {
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

    map.fitBounds(baseBounds);
    map.createPane('cp');
    map.getPane('cp').style.zIndex = 20;
    map.createPane('cpTooltip');
    map.getPane('cpTooltip').style.zIndex = 30;
    map.createPane('cpLines');
    map.getPane('cpLines').style.zIndex = 10;
    map.createPane('background');
    map.getPane('background').style.zIndex = 0;

    let map_image_name = layer_data["background"]["minimap_filename"];

    // console.log(mapTiles);
    // override tile URL template function to support loading our bundled tiles instead
    const TileLayerBundledTiles = L.TileLayer.extend({
        getTileUrl (coords) {
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
        }
    });

    new TileLayerBundledTiles(map_image_name, {
        tms: false,
        maxNativeZoom: 4,
        zoomOffset: zoomOffset,
        // scale tiles to match minimap width and height
        tileSize: tileSize,
        pane: 'background',
        bounds: baseBounds,
    }).addTo(map);

    // note which clusters appear on which lane, we need this to establish CP->Cluster relationship per-lane
    const clusters_on_lane = new Map();
    for (const lane in laneGraph) {
        const links = laneGraph[lane];
        clusters_on_lane.set(lane, new Set());
        links.forEach(link => {
            clusters_on_lane.get(lane).add(link["a"]);
            clusters_on_lane.get(lane).add(link["b"]);
        })
        allLanes.add(lane);
        // length of possible lane instance, without main CPs
        // TODO: Fallujah RAAS v1 lane lengths are wrong, better base it off of shortest path
        laneLengths.set(lane, links.length - 1);
    }
    // extract capture points from YAML data
    // this is also the set of vertices
    for (const cluster_name in raw_clusters) {

        const cluster = new Cluster();
        clusters.add(cluster);
        clustersByName.set(cluster_name, cluster);

        raw_clusters[cluster_name].forEach(cpRaw => {

            // create point, avoid duplicates
            let cp = new CapturePoint(
                cpRaw["sdk_name"],
                cpRaw["display_name"],
                [cpRaw["y"], cpRaw["x"]]
            );

            // if there is an equal, just use it instead of the current CP, discard current CP
            let foundEqual = false;
            capturePoints.forEach(cpOther => {
                if (cp.equal(cpOther)) {
                    foundEqual = true;
                    cp = cpOther;
                }
            })

            // add CP to CP-set and associate CP with cluster per-lane
            capturePoints.add(cp);
            for (const lane of clusters_on_lane.keys()) {
                if (clusters_on_lane.get(lane).has(cluster_name)) {
                    cluster.addPoint(cp, lane);
                }
            }
        });
    }

    // generate set of edges
    for (const lane in laneGraph) {
        laneGraph[lane].forEach(link => {
            const clusterA = clustersByName.get(link["a"]);
            const clusterB = clustersByName.get(link["b"]);

            clusterA.addEdgeTo(clusterB, lane);
        });
    }

    // find blufor and opfor main
    // assume that blufor main is always the first point of a lane and opfor main is the last point
    const first_lane = Object.values(laneGraph)[0]
    let bluforCluster = clustersByName.get(first_lane[0]["a"]);
    let opforCluster = clustersByName.get(first_lane[first_lane.length - 1]["b"]);

    cpBluforMain = [...bluforCluster.points][0];
    cpOpforMain = [...opforCluster.points][0];


    ownMain = new CapturePoint("dummy main", "dummy main", [0.0, 0.0]);

    // create markers for capture points
    capturePoints.forEach(cp => {
        const circleMarker = L.circleMarker(cp.pos, {
            radius: 20,
            pane: 'cp',
        });
        circleMarker.cp = cp;
        cp.circleMarker = circleMarker;
        circleMarker.on('click', ev => {
            cp.onClick()
        });
        circleMarker.addTo(map);
        circleMarker.on('mouseover', ev => {
            const tt = circleMarker.getTooltip();
            if (tt !== undefined) {
                // this will probably break at some point
                L.DomUtil.addClass(tt._container, 'mouseover');
            }
            // re-open tooltip to make sure text is still centered
            circleMarker.closeTooltip();
            circleMarker.openTooltip();
        })
        circleMarker.on('mouseout', ev => {
            const tt = circleMarker.getTooltip();
            if (tt !== undefined) {
                L.DomUtil.removeClass(tt._container, 'mouseover');
            }
            circleMarker.closeTooltip();
            circleMarker.openTooltip();
        })
    })

    redraw();

    // Debug
    if (window.location.hostname.startsWith("dev.")) {
        map.addEventListener('mousedown', function (ev) {
            const lat = ev.latlng.lat;
            const lng = ev.latlng.lng;
            console.log(`Pos: X=${lng} Y=${lat}`);
            console.log(map.getZoom());
        });
    }

    const mapDiv = document.getElementById("map");
    new ResizeObserver(() => {
        map.invalidateSize();
        map.fitBounds(baseBounds, {
            animate: false,
        });
    }).observe(mapDiv);
}

function validateMapName(map) {
    if (!raasData[map]) {
        throw new MapNotFoundError(`No map found named ${map}`);
    }
    return true;
}

function validateLayerName(map, layer) {
    if (!raasData[map][layer]) {
        throw new LayerNotFoundError(`No layer for ${map} found named ${layer}`);
    }
    return true;
}

function computeLaneProbabilities(point, possibleLanes) {
	let lanes = point.clusters;
	let laneProb = new Map();

	// Probability scaling
	let totalProb = 0;

	// Compute P(lane && point) for each lane
	lanes.forEach((cluster, lane) => {
            // ignore impossible lanes
            if (!possibleLanes.has(lane)) {
                return;
            }
            let prob = 1/cluster.points.size;
            totalProb += prob;
            laneProb.set(lane, prob);
	});
	// Rescales probabilities to sum to 1
	laneProb.forEach((prob, lane) => {
		laneProb.set(lane, (laneProb.get(lane)/totalProb));
	});
	return laneProb;
}

function toPercent(number) {
    return Math.round(number*100);
}

class MapNotFoundError extends Error {}
class LayerNotFoundError extends Error {}
