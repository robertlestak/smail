#!/bin/bash
set -e

createBuilder() {
    export BUILDER=b-`uuidgen`
    docker buildx create --use --name $BUILDER
    docker buildx inspect --bootstrap
}

cleanup() {
  docker buildx rm $BUILDER
}

trap cleanup EXIT

createBuilder

IMAGE=registry.lestak.sh/smail

TAG=$GIT_COMMIT

PLATFORMS=linux/amd64

echo "Building $IMAGE:$TAG for $PLATFORMS"

bash /bin/build.sh . \
    -f devops/docker/Dockerfile \
    --platform $PLATFORMS \
    --progress plain \
    --output type=image,name=$IMAGE:$TAG,push=true

echo "Deploying..."

sed -e "s,$IMAGE:.*,$IMAGE:$TAG,g" \
  devops/k8s/*.yaml | kubectl apply -f -
