<template lang="html">
  <div> 
    <div class="lane-percentages card">
      <div v-for="laneName in Object.keys(currentLanePercentages)" class="lane">
        <label>{{ laneName }}</label>
        <span>{{ currentLanePercentages[laneName] }}</span>
      </div>
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
      console.log({percentages});
    });
    console.log(this.currentLanePercentages);
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
  props: {
    map: Object,
  },
  computed: {
  }
});
</script>

<style lang="scss" scoped>
.lane-percentages {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  height: min-content;
  font-size: smaller;
}

.lane-percentages > * {
  padding: 10px;
}

.lane {
  display: flex;
  flex-direction: column;
  align-items: center;
}


</style>
