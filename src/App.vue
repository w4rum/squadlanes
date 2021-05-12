<template lang="html">
  <div>
    <span class="overlay top-center"> <lane-percentages :map="map"></lane-percentages> </span>
    <span class="overlay top-right"
      ><layer-select
        :map="map"
        :startingMapName="startingMapName"
        :startingLayerName="startingLayerName"
      ></layer-select
    ></span>
    <span class="overlay bottom-center"><map-legend></map-legend></span>
    <span class="overlay bottom-right"><about-modal></about-modal></span>
  </div>
</template>

<script>
import Vue from "vue";
import { BootstrapVue, IconsPlugin } from "bootstrap-vue";
import "bootstrap/dist/css/bootstrap";
import "bootstrap-vue/dist/bootstrap-vue";

import * as map from "./map";
import LanePercentages from "./LanePercentages";
import LayerSelect from "./LayerSelect";
import AboutModal from "./AboutModal";
import MapLegend from "./MapLegend";

Vue.use(BootstrapVue);
Vue.use(IconsPlugin);

export default Vue.extend({
  data() {
    return {
      map,
      startingMapName: "Narva",
      startingLayerName: "RAAS v1",
    };
  },
  components: {
    LanePercentages,
    LayerSelect,
    AboutModal,
    MapLegend,
  },
});
</script>

<style lang="scss">
#map {
  position: fixed;
  width: 100vw;
  height: 100vh;
}

.overlay {
  padding: 10px;
}

.top-center {
  position: fixed;
  top: 0;
  left: calc(50vw - 25vw);
  width: 50vw;
}

.top-right {
  position: fixed;
  top: 0;
  right: 0;
}

.bottom-center {
  position: fixed;
  width: 30vw;
  bottom: 0;
  left: calc(50vw - 15vw);
}

.bottom-right {
  position: fixed;
  bottom: 0;
  right: 0;
}

.tweaked-dropdown .dropdown-toggle {
  height: min-content;
}

.right-elt-wrapper,
.left-elt-wrapper {
  width: 20vw;
  display: flex;
  > * {
    flex-wrap: nowrap;
    z-index: 500;
  }
}
.right-elt-wrapper {
  justify-content: flex-end;
}
.left-elt-wrapper {
  justify-content: flex-start;
}

.button-overlay {
  pointer-events: none;
  position: fixed;
  width: 100vw;
  height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.top-elts,
.bottom-elts {
  padding: 10px;
  display: flex;
  justify-content: space-between;
}

.cpTooltip {
  background-color: transparent !important;
  border: none !important;
  box-shadow: 0 0 0 transparent !important;
  font-weight: bold;
  text-shadow: -1px 1px 0 white, 1px 1px 0 white, 1px -1px 0 white, -1px -1px 0 white;
  text-align: center;
  line-height: 10px;
  resize: none;
}

.cpTooltip.mouseover {
  text-shadow: -1px 1px 0 black, 1px 1px 0 black, 1px -1px 0 black, -1px -1px 0 black;
  color: white;
}

.cpTooltipName {
  font-size: 12px;
}

.mouseover .cpTooltipName {
  font-size: 15px;
}

.cpTooltipDepth {
  padding-top: 20px;
  font-size: 25px;
  font-family: "Impact", sans-serif;
}

.cpTooltipLanes {
  padding-top: 23px;
  font-size: 12px;
}

.mouseover .cpTooltipLanes {
  font-size: 15px;
}

.map-control {
  width: 100%;
  height: 8rem;
  margin-bottom: 1rem;
}

.map-menus {
  float: right;
  width: 50%;
  height: 100%;
}

.laneHeader {
  border-bottom: 1px solid;
  width: 100%;
  margin-bottom: 0.4rem;
}

.lane-control {
  float: left;
  width: 50%;
  border: 1px solid;
  border-right: 0px;
  height: 100%;
  padding: 1rem;
}

.lane.possible {
  color: #36b136;
}

.lane.impossible {
  color: #838383;
}

.modal-backdrop {
  opacity: 30%;
}


@media only screen and (max-width: 850px) {
  // .top-right {
  //   padding-left: 60px;
  // }
  
  .top-center {
    top: 47px;
  }
}

.leaflet-tooltip-top:before,
.leaflet-tooltip-bottom:before,
.leaflet-tooltip-left:before,
.leaflet-tooltip-right:before {
    content: none;
}

.leaflet-container {
    background-color:rgba(255,0,0,0.0);
}
</style>
