export type LayerData = {
  background: {
    corners: [{ x: number; y: number }, { x: number; y: number }];
    minimap_filename: string;
  };

  clusters: {
    [clusterName: string]: {
      display_name: string;
      sdk_name: string;
      x: number;
      y: number;
    }[];
  };

  lanes: {
    [laneName: string]: { a: string; b: string }[];
  };

  mains: [string, string];
};

export type RaasData = {
  [mapName: string]: {
    [layerName: string]: LayerData;
  };
};

// @ts-ignore
export let raasData: RaasData = require("../assets/raas-data.yaml");
