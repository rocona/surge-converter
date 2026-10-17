#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

IMAGE="${IMAGE:-ghcr.io/rocona/surge-converter}"
TAG="${TAG:-$(git rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%d%H%M%S)}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
PUSH="${PUSH:-1}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required (Docker Desktop or a Docker-compatible CLI)." >&2
  exit 1
fi

if [[ "$PUSH" != "0" && "$PUSH" != "1" ]]; then
  echo "PUSH must be 0 or 1 (received: $PUSH)." >&2
  exit 2
fi

if [[ "$PUSH" == "0" && "$PLATFORMS" == *,* ]]; then
  echo "PUSH=0 only supports one platform; set PLATFORMS=linux/amd64 (or another single platform)." >&2
  exit 2
fi

if ! docker buildx inspect >/dev/null 2>&1; then
  docker buildx create --use --name surge-converter-builder >/dev/null
fi

tags=(--tag "${IMAGE}:${TAG}")
if [[ "$TAG" != "latest" ]]; then
  tags+=(--tag "${IMAGE}:latest")
fi

args=(buildx build --platform "$PLATFORMS" "${tags[@]}" --build-arg "VCS_REF=${TAG}")
if [[ "$PUSH" == "1" ]]; then
  args+=(--push)
else
  args+=(--load)
fi

echo "Building ${IMAGE}:${TAG} for ${PLATFORMS} (push=${PUSH})"
docker "${args[@]}" .
