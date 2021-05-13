<template lang="html">
  <div class="map-legend">
    <b-button v-b-popover.click.top="popoverConfig" title="Popover Title"
      >Legend</b-button
    >
  </div>
</template>

<script>
import Vue from "vue";
export default Vue.extend({
  computed: {
    popoverConfig() {
      return {
        title: "Legend",
        html: true,
        content: `
          <span style="background: rgb(186,0,255)">&nbsp&nbsp&nbsp&nbsp</span> - Mid Point<br/>
          <span style="background: rgb(0,55,255);">&nbsp&nbsp&nbsp&nbsp</span> - Frontline Defense Point<br/>
          <span style="background: rgb(47,182,255);">&nbsp&nbsp&nbsp&nbsp</span>
          <span style="background: rgb(145,245,220);">&nbsp&nbsp&nbsp&nbsp</span>
          <span style="background: rgb(161,250,186);">&nbsp&nbsp&nbsp&nbsp</span>
          - Backline Defense Points<br/>
          <span style="background: rgb(255,0,0);">&nbsp&nbsp&nbsp&nbsp</span> - Frontline Offense Point<br/>
          <span style="background: rgb(255,162,92);">&nbsp&nbsp&nbsp&nbsp</span>
          <span style="background: rgb(252,227,108);">&nbsp&nbsp&nbsp&nbsp</span>
          <span style="background: rgb(253,246,203);">&nbsp&nbsp&nbsp&nbsp</span>
          - Backline Offense Points<br/>
          <span style="background: rgb(176,255,148);">&nbsp&nbsp&nbsp&nbsp</span> - Possible Next Point
          (Clickable)<br/>
          <span style="background: rgb(0,255,13)">&nbsp&nbsp&nbsp&nbsp</span> - Confirmed Point<br/>
            
        `,
      };
    },
  },
});
</script>

<style scoped>
.map-legend {
  display: flex;
  flex-direction: column;
  align-items: center;
}
</style>
