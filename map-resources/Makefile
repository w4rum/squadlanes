TILES_DIR=tiles
INPUT_PSD=einteilung_komplett_v4.psd

default: docker-prep $(patsubst full-size/%.jpg, $(TILES_DIR)/%, $(wildcard full-size/*.jpg))

docker-prep:
	docker pull osgeo/gdal

$(TILES_DIR)/%: full-size/%.jpg
	mkdir -p $@
	docker run \
		--mount type=bind,source=$(PWD),target=/mnt/map-resources \
		osgeo/gdal \
		gdal2tiles.py \
		--xyz \
		--profile=raster \
		--processes=16 \
		--zoom=0-6 \
		--s_srs=xyz \
		/mnt/map-resources/$< /mnt/map-resources/$@


.PHONY: clean
clean:
	sudo rm -rf $(TILES_DIR)
