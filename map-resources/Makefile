TILES_DIR=tiles

define tile
	mkdir -p $(1)
	docker run \
		--mount type=bind,source=$(PWD),target=/mnt/map-resources \
		osgeo/gdal \
		gdal2tiles.py \
		--xyz \
		--profile=raster \
		--processes=16 \
		--zoom=0-6 \
		/mnt/map-resources/$(2) /mnt/map-resources/$(1)
endef

default: docker-prep \
	$(patsubst full-size/%.tga, $(TILES_DIR)/%, $(wildcard full-size/*.tga)) \
	$(patsubst full-size/%.png, $(TILES_DIR)/%, $(wildcard full-size/*.png))

docker-prep:
	docker pull osgeo/gdal

$(TILES_DIR)/%: full-size/%.tga
	$(call tile,$@,$<)

$(TILES_DIR)/%: full-size/%.png
	$(call tile,$@,$<)


.PHONY: clean
clean:
	sudo rm -rf $(TILES_DIR)
