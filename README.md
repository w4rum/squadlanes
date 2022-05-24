# [Squad Lanes](https://squadlanes.com)
##### Interactive Squad Maps to help with RAAS capture point prediction

Capture Points and RAAS lanes are automatically extracted from Squad maps.

If you spot any specific errors, please open an issue!
That helps us get an overview.

## Usage
See [Captain's video](https://youtu.be/OFGYkDxdRYE?t=498) to find out how to work with our official deployment at [squadlanes.com](https://squadlanes.com).

## Deployment with Docker and docker-compose

The project contains one container for the extraction process and one container for the frontend.

### Extraction Container

1. Adjust the path to your local squad folder in the `docker-compose.yml`
   ```shell
   volumes:
      - "PATH/TO/SQUAD:/opt/squadgame" # <-- Only change the path left of the column!
   ```
2. Start the container with
   ```shell
   docker compose up extraction -d
   ```
3. Enter the container with an interactive bash
   ```shell
   docker compose exec -it extraction bash
   ```
4. Now you can follow the [deployment](#deployment) instructions within this container. Start with step 2 of [Extracting map images and layer data](#extracting-map-images-and-layer-data)

### Frontend Container

1. Start the container with `docker compose up web -d`.
2. Install npm dependencies with `docker compose exec web npm install`
3. Start the npm development server with `docker compose exec web npm start`
4. Access the frontend on http://localhost:1234

## Deployment
In order to run your own instance of Squad Lanes, you need to
1. Extract the map images and layer data with our Python extraction scripts
2. Package the static files with ParcelJS
3. Deploy the static files to a web server, e.g., nginx

These tasks are futher explained in the following sections.
We only provide a deployment guide for Linux systems.
If you're using another operating system, then you're on your own.

Note that if you're trying to port this to a different operating system,
the `umodel-squadlanes` executable included in this repository is not from the
original [UEViewer project](https://github.com/gildor2/UEViewer) but instead
from [our own fork](https://github.com/w4rum/UEViewer).
Our version behaves very differently and the original `umodel` executable will
*not* work for our use case.
You have to use our fork to build an executable for your operating system.

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
    - Wine 6.9 or compatible
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
8. The map tiles are now in `src/assets/map-tiles` if you're using the default config.
    The layer data was saved to `extraction/raas-data-auto.yml`.
    If you want to, you can make manual changes to the layer data.
    Once you're done, overwrite the existing file in `src/assets/raas-data.yaml`.
    Note that instead of using the layer data you just generated, you can also just use
    the layer data included in this repository.
    The important part of this process is the extraction of the map tiles, which are too
    big (~1 GiB) to be included here.
   
If any of these steps don't seem to work, e.g., `poetry run tiles` finishes instantly but doesn't 
actually produce any tiles, then open the config file, set `LOG_LEVEL = "debug"` and try again.
That should provide you with more verbose output.

### Web Server Deployment

If you want to deploy this locally to change the front-end files and test around, follow the
"Development" instructions.

If you want to deploy this to a production server, follow the "Production" instructions.

#### Development
1. Run `npm run start`.
2. ParcelJS will now package the static files.
   This can take a couple of minutes on your first run.
3. The development server can now be reached at `http://localhost:1234/`.
   Changing any files while the server is running will cause an automatic update.
   However, you might still need to hit F5 for some parts, e.g., changes to the map
   logic.
   
#### Production
1. Run `npm run build`.
2. ParcelJS will now package the static files.
   This can take a couple of minutes on your first run.
3. The packaged static files are now in `dist/`.
4. Upload the contents of `dist/` into your server's webroot and make your web server
   return the `index.html` that you just uploaded.
   
If you want a nice and easy way to delta-upload your `dist` directory to your web server
with `rsync`, take a look at the `deploy` command in `package.json` and adjust that to
your needs.

## Documentation / Project overview for developers
This project is in a somewhat unpolished and largely undocumented state.
We apologize for this but don't have specific plans to fix this in the immediate future
since the person responsible for most of the code including the extraction scripts 
(Tim | w4rum) hasn't actively played Squad in quite a while and has moved to a kind
of maintenance-only mode for this project.
If you want to contribute at this point in time, feel free to open issues and pull
requests and we'll be happy to work with you.
Just be warned, it's probably a lot of work to get into it.


## Attribution and Licenses
- Squad map backgrounds and capture point information were extracted from game files
  shipped through Steam.
  We hope our usage here is fine.
  If it is not, please contact w4rum via [email](mailto:tim.schmidt@khorne.faith) or
  Discord DM (`Tim | w4rum#4344`, reach me via https://discord.gg/aM5CYjnFxN)
- [Leaflet](https://github.com/Leaflet/Leaflet). Released under
  [BSD 2-Clause "Simplified" License](https://github.com/Leaflet/Leaflet/blob/master/LICENSE).
- Bootstrap. Copyright 2013-2020 Start Bootstrap LLC. Code released under the
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
