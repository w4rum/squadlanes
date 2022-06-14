<template lang="html">
  <div class="card bg-dark">
    <div class="text-white text-center small m-1">
      <a
        title="We've implemented a new not-yet-perfect prediction logic that
should support all kinds of layers OWI might throw at us.
Unfortunately, it's a bit too permissive on the new layers right now.
You might, e.g., see a 15-point path on Gorodok RAAS v11 that most
likely is not actually possible in-game.

We're working on identifying the correct restrictions to accurately map
the in-game experience.

For now, though, we've released the new logic anyways because the old logic
completely broke down on the new layers.

Old layers should not be affected and work just fine."
      >
        Squad v2.16
        <span class="text-warning"> &#x26a0;</span></a
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
