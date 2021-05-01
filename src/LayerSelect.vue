<template lang="html">
  <div class="layer-selection">
    <b-form-input ref="mapDatalistInput" list="map-datalist" id="map-datalist-input" v-model="currMapNameInput" v-on:change="onSelectMap" v-on:focus="onFocusMapFilterInput"></b-form-input>
    <b-form-datalist ref="mapDatalist" id="map-datalist" v-model="currMapName" :options="mapNames"></b-form-datalist>
    <b-dropdown id="layer-dropdown" class="tweaked-dropdown" :text="currLayerName">
      <b-dropdown-item
        v-for="layer in Object.keys(map.raasData[currMapName])"
        v-on:click="selectLayer(layer)"
      >
        {{ layer }}
      </b-dropdown-item>
    </b-dropdown>
  </div>
</template>

<script>
import Vue from "vue";
import { BootstrapVue, IconsPlugin } from "bootstrap-vue";
import "bootstrap/dist/css/bootstrap";
import "bootstrap-vue/dist/bootstrap-vue";

Vue.use(BootstrapVue);
Vue.use(IconsPlugin);

export default Vue.extend({
  props: {
    map: Object,
    startingMapName: String,
    startingLayerName: String,
  },
  created() {
    this.mapNames = Object.keys(this.map.raasData);
    this.currMapName = this.startingMapName;
    this.currMapNameInput = this.currMapName;
    this.currLayerName = this.startingLayerName;
  },
  data() {
    return {
      currMapName: null,
      currLayerName: null,
      mapNames: null,
      currMapNameInput: '',
    };
  },
  methods: {
    selectMap(map) {
      console.log("selected ", map);
      this.currMapName = map;
      this.currMapNameInput = this.currMapName;
      this.map.changeMap(this.currMapName, Object.keys(this.map.raasData[this.currMapName])[0]);
    },
    selectLayer(layer) {
      console.log({ layer });
      this.currLayerName = layer;
      this.map.changeMap(this.currMapName, this.currLayerName);
    },
    filterMap() {
      console.log('event: ', this.filterMapInput);
      this.mapNames = Object.keys(this.map.raasData).filter(mapName => {
        const normalized = mapName.toLowerCase().replace(' ', '');
        const normalizedFilter = this.filterMapInput.toLowerCase().replace(' ', '');
        return normalized.includes(normalizedFilter);
      });
    },
    onInputFilterSubmit() {
      console.log('submitted!');
      if (this.mapNames.length > 0) {
      }
    },
    onFocusMapFilterInput() {
      this.currMapNameInput = '';
    },
    onSelectMap(newMap) {
      this.$refs.mapDatalistInput.$el.blur();
      this.selectMap(newMap);
    }
  },
});
</script>

<style lang="scss">
.layer-selection {
  display: flex;
  flex-wrap: nowrap;
}

.layer-selection > :first-child {
  margin-right: 10px;
}


.dropdown-filter {
  padding: .25em;
}


</style>
