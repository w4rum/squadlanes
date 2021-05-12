<template lang="html">
  <div class="lane-percentages card bg-dark">
    <div v-for="laneName in Object.keys(currentLanePercentages)" class="lane"
         :style="laneColor(currentLanePercentages[laneName])">
      <label>{{ laneName }}</label>
      <span>{{ currentLanePercentages[laneName] }}%</span>
    </div>
  </div>

</template>
<script>
import { BehaviorSubject, Subscription } from "rxjs";
import Vue from "vue";

export default Vue.extend({
  props: {
    map: Object,
  },
  created () {
    const subscription = this.map.lanePercentages.subscribe((percentages) => {
      this.currentLanePercentages = percentages;
    });
    this.subscription.add(subscription);
  },
  destroyed() {
    this.subscription.unsubscribe();
  },
  data() {
    return {
      subscription: new Subscription(),
      currentLanePercentages: null,
    }
  },
    methods: {
      laneColor(lanePercentage) {
          if (lanePercentage === 0) {
            return "color: hsl(0, 0%, 50%);"
          }

          // we map lanePercentage in [0, 100] to hue in [RED_HUE, GREEN_HUE]
          // note that RED_HUE is 0, so we don't actually have to put that into the formula
          const GREEN_HUE = 120;

          const cur_hue = lanePercentage / 100 * GREEN_HUE;

          return `color: hsl(${cur_hue}, 100%, 50%);`;
      }
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
