<template lang="html">
  <div>
    <b-button v-b-modal.about-modal class="about-button">?</b-button>
    <b-modal id="about-modal" title="About" ok-only>

            <p>
                <a target="_blank" rel="noopener noreferrer" href="https://youtu.be/OFGYkDxdRYE?t=498">
                    How the fuck do I use this?</a>
            </p>
            <p>
                If you want to explore or contribute to this project, feel free to check out the code in
                <a href="https://github.com/w4rum/squadlanes" target="_blank" rel="noopener noreferrer">our repository
                    on GitHub</a> and
                <a href="https://docs.google.com/spreadsheets/d/1dz4ryDm7vQnbm4dI19Qfuo9ISLt4UK6GyYXXwwolvRw/"
                   target="_blank" rel="noopener noreferrer">
                    our spreadsheet</a> with all the RAAS data.
                If you want to build something on top of what we've done here, you can always find the latest RAAS data
                that we use on this website <a href="raas-data.yaml" target="_blank" rel="noopener noreferrer">here</a>.
            </p>
            <p>
                If you spot any specific errors, please head over to our GitHub repository and open an issue!
                That helps us get an overview.
            </p>
            <p>
              This project was made possible by the contributions of the following individuals:
              <ul>
                  <li>
                      Tim | w4rum: Scripts for automatic extraction of capture points, lanes, etc.,
                      implementation of the website, UI design
                  </li>
                  <li>
                      Captain, Angatar, RacialConfusion: Countless hours of research into RAAS lanes and manual refinement
                      of the data used here, UI design
                  </li>
              </ul>
            </p>
    </b-modal>
  </div>
</template>

<script>
import Vue from "vue";
export default Vue.extend({ });
</script>

<style scoped>

.about-button {
  border-radius: 50%;
  width: 40px;
  height: 40px;
  padding: unset;
}


</style>
