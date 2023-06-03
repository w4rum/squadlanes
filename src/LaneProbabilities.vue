<template lang="html">
  <div class="card bg-dark">
    <div class="text-white text-center small m-1">
      Squad v4.5
    </div>
    <div
      v-if="selection.layer.startsWith('HLP')"
      class="text-warning text-center small m-1"
    >
      <a
        href="https://steamcommunity.com/sharedfiles/filedetails/2442357787"
        target="_blank"
      >
        Hawk's Layer Pack
      </a>
      <a
        title="Added in cooperation with EyeOfTheHawks.
These layers might be more unstable and will process *much* slower than the vanilla layers.
(We'll fix the performance issues sometime in the future. Maybe.)

Squadlanes accurately shows the HLP layers, accounting for HLP's custom logic.

The only thing currently not visualized (for HLP and Vanilla) are capture point probabilities."
      >
        <b-icon-question-circle
      /></a>
    </div>
    <div class="text-muted text-center small m-1">
        Logic: {{ mapData.logic }}
    </div>
    <div v-if="mapData.logic === 'Multiple Lanes'" class="lane-percentages">
      <div class="lane" :style="laneColor(lane)" v-for="lane in mapData.lanes">
        <label>{{ lane.name }}</label>
        <span>{{ Math.floor(lane.probability * 100) }}%</span>
      </div>
    </div>
  </div>
</template>
<script>
import Vue from "vue";
import { BIconQuestionCircle } from "bootstrap-vue";

export default Vue.extend({
  components: {
    BIconQuestionCircle,
  },
  props: {
    mapData: Object,
    selection: {
      map: String,
      layer: String,
    },
  },
  methods: {
    laneColor(lane) {
      if (lane.probability === 0) {
        return "color: hsl(0, 0%, 50%);";
      }

      // we map lanePercentage in [0, 1] to hue in [RED_HUE, GREEN_HUE]
      // note that RED_HUE is 0, so we don't actually have to put that into the formula
      const GREEN_HUE = 120;

      const cur_hue = lane.probability * GREEN_HUE;

      return `color: hsl(${cur_hue}, 100%, 50%);`;
    },
  },
});
</script>

<style lang="scss" scoped>
.lane-percentages {
  display: flex;
  flex-direction: row;
  height: min-content;
  font-size: smaller;
  width: min-content;
  height: min-content;
  margin: auto;
}

.lane-percentages > * {
  padding: 5px;
}

.lane {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.lane label {
  font-size: smaller;
  margin: unset;
}
</style>
