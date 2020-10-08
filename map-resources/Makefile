TILES_DIR=tiles

default: docker-prep $(patsubst full-size/%.tga, $(TILES_DIR)/%, $(wildcard full-size/*.tga))

docker-prep:
	docker pull osgeo/gdal

$(TILES_DIR)/%: full-size/%.tga
	mkdir -p $@
	docker run \
		--mount type=bind,source=$(PWD),target=/mnt/map-resources \
		osgeo/gdal \
		gdal2tiles.py \
		--xyz \
		--profile=raster \
		--processes=16 \
		--zoom=0-6 \
		/mnt/map-resources/$< /mnt/map-resources/$@


.PHONY: clean
clean:
	sudo rm -rf $(TILES_DIR)
