# This will be run inside the Docker container when you run
#  poetry run tiles
#
# DO NOT RUN THIS ON YOUR HOST SYSTEM!

# Add a user and group with the same UID / GID inside the container so that the
# generated tiles are owned by us and not root
groupadd --gid $2 --non-unique ze-group
useradd --uid $1 --non-unique ze-user
runuser --group=ze-group -u ze-user -- \
  gdal2tiles.py \
  --xyz \
  --profile=raster \
  --processes=16 \
  --zoom=0-6 \
  /mnt/map-fullsize/$3.tga \
  /mnt/map-tiles/$3 \
