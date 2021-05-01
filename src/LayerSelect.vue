<template lang="html">
  <div class="layer-selection">
    <b-dropdown id="map-dropdown" ref="mapDropdown" class="tweaked-dropdown" :text="currMapName">
      <b-dropdown-form v-on:submit.prevent="onInputFilterSubmit">
        <b-form-group label="" label-for="map-filter">
          <b-form-input
            id="map-filter"
            size="sm"
            ref="mapFilterInput"
            v-on:input="filterMap"
            v-model="filterMapInput"
          > 
        </b-form-group>
      </b-dropdown-form>
      <b-dropdown-item v-for="map in mapNames" v-on:click="selectMap(map)">
        {{ map }}
      </b-dropdown-item>
    </b-dropdown>
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
  mounted() {
    this.$root.$on('bv::dropdown::shown', bvEvent => {
      console.log('Dropdown is about to be shown', bvEvent)
      console.log('refs: ', this.$refs);
      console.log('id: ', bvEvent.$el.id);
      // if (bvEvent.$el.id === "map-dropdown") {
      //   this.$refs.mapFilterInput.focus()
      //   console.log('focus?');
      // }
    })
  },
  props: {
    map: Object,
    startingMapName: String,
    startingLayerName: String,
  },
  created() {
    this.mapNames = Object.keys(this.map.raasData);
    this.currMapName = this.startingMapName;
    this.currLayerName = this.startingLayerName;
  },
  data() {
    return {
      currMapName: null,
      currLayerName: null,
      mapNames: null,
      filterMapInput: '',
    };
  },
  methods: {
    selectMap(map) {
      console.log("selected ", map);
      this.currMapName = map;
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
        this.selectMap(this.mapNames[0]);
        this.$refs.mapDropdown.hide(true);
      }
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
