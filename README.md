# [Squad Lanes](https://squadlanes.com)
##### Interactive Squad Maps to help with RAAS capture point prediction

This is a work-in-progress.

Capture Points and RAAS lanes are automatically extracted from Squad maps.

If you spot any specific errors, please open an issue!
That helps us get an overview.

## Usage
See [Captain's video](https://youtu.be/OFGYkDxdRYE?t=498) to find out how to work with our official deployment at [squadlanes.com](https://squadlanes.com).

## Deployment
In order to run your own instance of Squad Lanes, you need to
1. Extract the map images and layer data with our Python extraction scripts
2. Run the webserver using NodeJS and Parcel

Both of these tasks are futher explained in the following sections.
We only provide a deployment guide for Linux systems.
If you're using another operating system, then you're on your own.

### Extracting map images and layer data
Even though we only need map layer data and map images, we're unpacking most of the
game files, which will take up about 70 GiB of additional space.
Make sure you have that available.
You can change the config parameters in step 4 if you need to write to another
drive.

1. Install the following dependencies:
    - Python 3.8 or compatible
    - [Poetry](https://python-poetry.org/) 1.1.5 or compatible
    - Docker 20.10.5 or compatible
2. Move into the extraction sub-project:
    ```shell
    cd extraction  
    ```
3. Install the virtual environment and dependencies with Poetry
    ```shell
    # (Optional) Configure Poetry to create the virtual environment inside the project directory.
    # This will make sure the project stays self-contained.
    poetry config virtualenvs.in-project true

    poetry install
    ```
4. Edit `extraction/squadlanes_extraction/config.py`.
    You will probably have to change at least the required settings.
5. Unpack / decrypt the steam-distributed game files.
    This can take a couple of minutes.
    ```shell
    poetry run unpack
    ```
6. Extract the full-size map images and layer data from the unpacked game files.
    This should only take about a minute.
    ```shell
    poetry run extract
    ```
7. Split the full-size map images into smaller tiles for lazy loading.
    ```shell
    poetry run tiles
    ```
8. The map tiles are now in the web assets directory if you're using the default config.
    The layer data was saved to `extraction/raas-data-auto.yml`.
    You can make manual changes to that if necessary.
    Once you're done, overwrite the existing file in `src/assets/raas-data.yaml`.
    You don't *have* to overwrite the existing file and can just use that one instead.
    The important part of this process is the extraction of the map tiles.

### Web Server Deployment

TODO

## Documentation / Project overview for developers
This project is in somewhat unpolished and largely undocumented state.
We apologize for this but don't have specific plans to fix this in the immediate future
since the person responsible for the extraction scripts hasn't actively played Squad in
quite a while and has moved to a kind of maintenance-only mode for this project.
If you want to contribute at this point in time, feel free to open issues and pull
requests.
Just be warned, it's probably a lot of work to get into it.


## Attribution and Licenses
- Squad map backgrounds and capture point information were extracted from game files
  shipped through Steam.
  We hope our usage here is fine.
  If it is not, please contact w4rum via [email](mailto:tim.schmidt@khorne.faith) or
  Discord DM (`Tim | w4rum#4344`, reach me via https://discord.gg/aM5CYjnFxN)
- [Leaflet](https://github.com/Leaflet/Leaflet). Released under
  [BSD 2-Clause "Simplified" License](https://github.com/Leaflet/Leaflet/blob/master/LICENSE).
- Bootstrap and the "Simple Sidebar" component: Copyright 2013-2020 Start
  Bootstrap LLC. Code released under the
  [MIT](https://github.com/StartBootstrap/startbootstrap-simple-sidebar/blob/gh-pages/LICENSE)
  license.
- This project relies on Konstantin Nosov's
  [UEViewer](https://github.com/gildor2/UEViewer) which is currently not covered by a
  license.
  We use [our own fork](https://github.com/w4rum/UEViewer) that we have modified
  slightly to better fit our use case.
- [Leaflet.TileLayer.NoGap](https://github.com/Leaflet/Leaflet.TileLayer.NoGap) by
  Iván Sánchez Ortega, released under the
  [Beer-Ware License](https://github.com/Leaflet/Leaflet.TileLayer.NoGap/blob/master/LICENSE).
  (Where do we send that beer?)
- The original contributions found in this repository are released under AGPLv3
  (see LICENSE).
