#!/bin/sh

echo "### BUILD"
docker build --file deployment/Dockerfile -t ghcr.io/w4rum/squadlanes .

echo "### PUSH"
echo "This will fail if you have not logged into the GitHub registry by using"
echo "docker login ghcr.io -u USERNAME"
docker push ghcr.io/w4rum/squadlanes:latest

echo "### DONE!"
