<template lang="html">
  <div>
    <b-button v-b-modal.about-modal class="about-button">?</b-button>
    <b-modal id="about-modal" title="About" ok-only>
      <p>
        <i> Squad Lanes v2.2.1 (for Squad v2.16) </i>
      </p>
      <p>
        <a
          target="_blank"
          rel="noopener noreferrer"
          href="https://youtu.be/OFGYkDxdRYE?t=498"
        >
          How the fuck do I use this?</a
        >
      </p>
      <p>
        If you want to explore or contribute to this project, feel free to check
        out the code in
        <a
          href="https://github.com/w4rum/squadlanes"
          target="_blank"
          rel="noopener noreferrer"
          >our repository on GitHub</a
        >
        and
        <a
          href="https://docs.google.com/spreadsheets/d/1dz4ryDm7vQnbm4dI19Qfuo9ISLt4UK6GyYXXwwolvRw/"
          target="_blank"
          rel="noopener noreferrer"
        >
          our spreadsheet</a
        >
        with all the RAAS data that we collected manually (note that we no
        longer use this sheet as a data source and have moved to fully automatic
        data mining scripts). If you want to build something on top of what
        we've done here, you can always find the latest RAAS data that we use on
        this website
        <a
          href="https://raw.githubusercontent.com/w4rum/squadlanes/master/src/assets/raas-data.yaml"
          target="_blank"
          rel="noopener noreferrer"
          >here</a
        >.
      </p>
      <p>
        If you spot any specific errors, please head over to our GitHub
        repository and open an issue! That helps us get an overview.
      </p>
      <p>
        This project was made possible by the contributions of the following
        individuals:
      </p>
      <ul>
        <li>
          Tim | w4rum: Data mining scripts to automatically extract information
          about capture points, lanes, and map images, map UI
        </li>
        <li>
          grey275: Overall UI (Huge rework of the 2.0 UI, Vue.js framework,
          layer selection, popup menus, automatic scaling to screen size, ...)
        </li>
        <li>
          Captain, Angatar, RacialConfusion: Countless hours of research into
          RAAS lanes and manual refinement of the data used here, UI design
        </li>
        <li>sugordon: Conditional probability calculation</li>
      </ul>
      <p>Keyboard Shortcuts:</p>
      <ul>
        <li><mono>m</mono> - Open map selection</li>
        <li>l - open layer selection</li>
      </ul>
    </b-modal>
  </div>
</template>

<script>
import Vue from "vue";
export default Vue.extend({});
</script>

<style scoped>
.about-button {
  border-radius: 50%;
  width: 40px;
  height: 40px;
  padding: unset;
}
</style>
