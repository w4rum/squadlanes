<template lang="html">
  <div class="lane-percentages card">
    <div v-for="laneName in Object.keys(currentLanePercentages)" class="lane">
      <label>{{ laneName }}</label>
      <span>{{ currentLanePercentages[laneName] }}%</span>
    </div>
  </div>

</template>
<script>
import { BehaviorSubject, Subscription } from "rxjs";
import Vue from "vue";

export default Vue.extend({
  methods: {},
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
  computed: {
  }
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
