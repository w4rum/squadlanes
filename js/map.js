let capturePoints = null;
let possibleLanes = null;
let cpLines = null;
let map = null;

function add_image_overlay(map, name, add_immediately = true, callback) {
    return $.getJSON(`map/${name}.json`, function (data) {
        const bounds = [[data.y1, data.x1], [data.y2, data.x2]];
        const layer = L.imageOverlay(`map/${name}.png`, bounds);
        if (add_immediately)
            layer.addTo(map);
        if (callback !== undefined)
            callback(layer);
    })
}

function distance(posA, posB) {
    return Math.sqrt(
        Math.pow(posA[0] - posB[0], 2)
        + Math.pow(posA[1] - posB[1], 2)
    )
}

function cpEqual(cpA, cpB) {
    return cpA["name"] === cpB["name"]
        || distance(cpA["pos"], cpB["pos"]) < 10.0
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

CP_POSSIBLE = 0
CP_CONFIRMED = 1
CP_IMPOSSIBLE = 2
CP_MANDATORY = 3

function updatePossibility(cp) {
    // ignore mandatory or confirmed points
    if (cp.status === CP_MANDATORY || cp.status === CP_CONFIRMED) {
        return
    }
    // If all of the CPs lanes are excluded
    if (intersection(cp.lanes, possibleLanes).size === 0) {
        cp.status = CP_IMPOSSIBLE;
        return;
    }
    // If another CP at the same depth is confirmed
    let sameDepthConfirmed = false;
    capturePoints.forEach(cpOther => {
        if (cpOther.status === CP_CONFIRMED && cpOther.depth === cp.depth) {
            sameDepthConfirmed = true;
        }
    })
    if (sameDepthConfirmed) {
        cp.status = CP_IMPOSSIBLE;
        return;
    }
    cp.status = CP_POSSIBLE;
}

function cpActive(cp) {
    let active = false;
    // check if cp has confirmed or mandatory neighbour
    capturePoints.forEach(cpOther => {
        if (cpOther !== cp
            && Math.abs(cpOther.depth - cp.depth) === 1
            && (cpOther.status === CP_CONFIRMED || cpOther.status === CP_MANDATORY)) {
            active = true;
        }
    })
    return active;
}

function cpColor(cp) {
    switch (cp.status) {
        case CP_CONFIRMED:
            return "rgb(102,202,193)";
        case CP_MANDATORY:
            return "rgb(102,202,127)";
        case CP_POSSIBLE:
            if (cpActive(cp)) {
                return "rgb(203,143,87)";
            } else {
                return "rgb(203,87,87)";
            }
        case CP_IMPOSSIBLE:
            return "rgb(145,145,145)";
    }
}

function redrawCpLines() {
    cpLines.forEach(line => {
        line.remove();
    })
    capturePoints.forEach(cp => {
        capturePoints.forEach(cpOther => {
            // only connect neighbouring CPs when both are confirmed or mandatory
            if (Math.abs(cp.depth - cpOther.depth) !== 1
                || (cp.status !== CP_MANDATORY && cp.status !== CP_CONFIRMED)
                || (cpOther.status !== CP_MANDATORY && cpOther.status !== CP_CONFIRMED)) {
                return;
            }
            const line = L.polyline([cp.pos, cpOther.pos], {
                color: "rgb(102,202,193)",
                pane: "cpLines",
            }).addTo(map);
            cpLines.add(line);
        });
    });

}

function cpOnclick(cp) {
    // Ignore clicks on mandatory and impossible CPs
    if (cp.status === CP_IMPOSSIBLE || cp.status === CP_MANDATORY) {
        return;
    }
    // Also ignore clicks on possible but inactive CPs
    if (cp.status === CP_POSSIBLE && !cpActive(cp)) {
        return;
    }
    if (cp.status !== CP_CONFIRMED) {
        // remove other lanes (unless point is lane-less)
        cp.status = CP_CONFIRMED;
        console.log(cp.lanes);
        if (!cp.lanes.has("")) {
            possibleLanes = intersection(possibleLanes, cp.lanes);
        }
    } else {
        cp.status = CP_POSSIBLE;
        // rebuild possible lanes
        possibleLanes = new Set();
        // add all lanes
        capturePoints.forEach(cp => possibleLanes = union(possibleLanes, cp.lanes));
        // intersect with confirmed points (don't intersect with lane-less points)
        capturePoints.forEach(cp => {
            if (cp.status === CP_CONFIRMED && !cp.lanes.has("")) {
                possibleLanes = intersection(possibleLanes, cp.lanes)
            }
        });
        console.log(possibleLanes);
    }
    // re-check possibility of all cps and re-color them
    capturePoints.forEach(cp => {
        updatePossibility(cp);
        cp.circleMarker.setStyle({color: cpColor(cp)});
        cp.circleMarker.redraw();
    });
    redrawCpLines();
}

//$.getJSON("map/base.json", function(base_format) {

// base map
/*
L.tileLayer('http://localhost:3000/map/tiles/base/{z}/{x}/{y}.png', {
    tms: false,
    tileSize: tile_size,
}).addTo(map);

// flags overlay
flags = new L.TileLayer('http://localhost:3000/map/tiles/flags/{z}/{x}/{y}.png', {
    tms: false,
    tileSize: tile_size,
});
 */

// borders image (for debugging)
// add_image_overlay(map, "borders");

function changeMap(map_name) {
    $.getJSON(`raas-lanes/${map_name}`, raas_lanes => {
        if (map !== null) {
            map.remove();
        }
        const bounds = raas_lanes["bounds"]
        const laneGraph = raas_lanes["lane_graph"]
        capturePoints = new Set();
        possibleLanes = new Set();
        cpLines = new Set();

        const baseBounds = [[bounds[0][1], bounds[0][0]], [bounds[1][1], bounds[1][0]]];
        const width = Math.abs(bounds[0][0] - bounds[1][0]);
        const height = Math.abs(bounds[0][1] - bounds[1][1]);

        const up_left_x = Math.min(bounds[0][0], bounds[1][0]);
        const up_left_y = Math.min(bounds[0][1], bounds[1][1]);
        const crs = L.extend({}, L.CRS.Simple, {
            // Move origin to upper left corner of map
            // need to do this because TileLayer always puts the left-upper corner on the origin
            transformation: new L.Transformation(1, -up_left_x, 1, -up_left_y),
        });

        map = L.map('map', {
            crs: crs,
            minZoom: -10,
            maxZoom: -7,
            zoomSnap: 0.1,
            zoomDelta: 1.0,
            dragging: true,
            boxZoom: true,
            scrollWheelZoom: true,
            touchZoom: true,
            zoomControl: true,
            doubleClickZoom: false,
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


        simple_map_name = map_name.substring(0, map_name.indexOf("_RAAS_"));
        CustomTileLayer = L.TileLayer.extend({
            /*
            getTileUrl: function(coords) {

                z = coords.z;
                console.log(coords);
                return "no";
            }

             */
        });

        // scale tiles to match map width and height
        // Our TileLayer stretches 4096*64 units by default (at zoom 0)
        // we just apply the scaling factor to the tile size to make it display correctly
        // TODO: this has someting to do with zoomOffset, explain that
        const tileSize = [256 * width/(4096*64*2), 256 * height/(4096*64*2)];
        new CustomTileLayer(`map-resources/tiles/${simple_map_name}/{z}/{x}/{y}.png`, {
            tms: false,
            minZoom: -10,
            maxZoom: -7,
            zoomOffset: 11,
            tileSize: L.point(tileSize),
            pane: 'background',
            bounds: baseBounds,
        }).addTo(map);
        //L.imageOverlay(`map-resources/full-size/${simple_map_name}.jpg`, baseBounds, {
        //    pane: 'background',
        //}).addTo(map);

        // extract capture points from JSON data
        for (const depth in laneGraph) {
            for (const lane in laneGraph[depth]) {
                laneGraph[depth][lane].forEach(cpRaw => {
                    cp = {
                        name: cpRaw["name"],
                        pos: [cpRaw["pos"][1], cpRaw["pos"][0]],
                        lanes: new Set([lane]),
                        depth: depth,
                        status: CP_POSSIBLE,
                        circleMarker: null,
                    };
                    let foundEqual = false;
                    capturePoints.forEach(cpOther => {
                        if (cpEqual(cp, cpOther)) {
                            foundEqual = true;
                            // This assumes that a capture point always has a unique
                            // depth even if it's present on multiple lanes
                            cpOther.lanes = union(cpOther.lanes, cp.lanes);
                        }
                    })
                    if (!foundEqual) {
                        capturePoints.add(cp);
                    }
                    possibleLanes.add(lane);
                })
            }
        }

        // mark mandatory points
        capturePoints.forEach(cp => {
            // only CPs on "" lane can be mandatory
            if (!cp.lanes.has("")) {
                return;
            }
            // if CP is the only CP in that cluster, it is mandatory
            let alone = true;
            capturePoints.forEach(cpOther => {
                if (cpOther.depth === cp.depth && cpOther !== cp) {
                    alone = false;
                }
            })
            if (alone) {
                cp.status = CP_MANDATORY;
            }
        })

        // create markers for capture points
        capturePoints.forEach(cp => {
            const cirlceMarker = L.circleMarker(cp.pos, {
                radius: 20,
                color: cpColor(cp),
                pane: 'cp',
            });
            cirlceMarker.cp = cp;
            cp.circleMarker = cirlceMarker;
            cirlceMarker.bindTooltip(
                `<div class="cpTooltipName">${_.startCase(cp.name).replaceAll(" ", "<br />")}</div>` +
                `<div class="cpTooltipDepth">${cp.depth}</div>` +
                `<div class="cpTooltipLanes">&nbsp${[...cp.lanes]}&nbsp</div>`, {
                    permanent: true,
                    direction: 'top',
                    opacity: 1.0,
                    className: 'cpTooltip',
                    pane: 'cpTooltip',
                    offset: [0, 50],
                }).openTooltip();
            cirlceMarker.on('click', ev => cpOnclick(cp));
            cirlceMarker.addTo(map);
        })

        redrawCpLines();

        // invisible regions layer for owner tooltip
        /*
        L.geoJSON(feature_collection, {
            onEachFeature: function (feature, layer) {
                layer.on('mouseover', function (e) {
                    document.getElementById("map-owner-display-name").innerHTML = feature.properties.owner;
                });
                layer.on('mouseout', function (e) {
                    document.getElementById("map-owner-display-name").innerHTML = "Bruderschaft Des Lichts";
                });
            },
            pane: 'tooltipPane',
            style : function(feature) {
                return {
                    fillOpacity: 0,
                    opacity: 0,
                }
            },
        }).addTo(map);
        map.addEventListener('mousemove', function (ev) {
            const lat = ev.latlng.lat;
            const lng = ev.latlng.lng;
            console.log(`Pos: ${lat} / ${lng}`);
            console.log(baseBounds);
        });
         */

        const mapDiv = document.getElementById("map");
        new ResizeObserver(() => {
            map.invalidateSize();
            map.fitBounds(baseBounds, {
                animate: false,
            });
        }).observe(mapDiv);
    });
}
