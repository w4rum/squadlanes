<template lang="html">
  <div class="card bg-dark">
    <div class="text-white text-center small m-1">
      <a
        title="We think we've fixed our previous problems with the path logic.

The data here should now match the in-game experience.

Please report any inconsistencies on our GitHub repository (link in the help section on the bottom-right)."
      >
        Squad v3.1
        <span class="text-warning"> &#9989;</span></a
      >
    </div>
    <div class="lane-percentages">
      <div class="lane" :style="laneColor(lane)" v-for="lane in lanes">
        <label>{{ lane.name }}</label>
        <span>{{ Math.floor(lane.probability * 100) }}%</span>
      </div>
    </div>
  </div>
</template>
<script>
import Vue from "vue";

export default Vue.extend({
  props: {
    lanes: Set,
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
