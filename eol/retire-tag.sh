#!/usr/bin/env bash
# Retire one published image tag by overwriting it with the end-of-life marker
# (eol/Dockerfile), on the multi-arch package and both per-architecture ones.
#
# APPROVAL IS REQUIRED, PER TAG, EVERY TIME.
#
#   Overwriting a published tag turns a consumer's green build red. That is the
#   entire point - it is how someone still building on a frozen image finds out
#   - but it is a decision, not a side effect, and the people it affects are not
#   in the room when this runs. Do not run this because a retention report
#   listed a tag; a report is a proposal. Get a human to approve that specific
#   image and tag first.
#
#   The marker is pushed over the tag. The previous image stays in the registry
#   addressable by digest, so anything pinned by digest is unaffected, but the
#   TAG no longer resolves to it and cannot be restored by this script.
#
# Dry run by default. It prints exactly what it would push and changes nothing
# until --push is given, and --push additionally requires --confirm to repeat
# the image and tag back.
#
# Usage:
#   eol/retire-tag.sh --image <name> --tag <tag> --replacement <ref> \
#                     --reason <one line> [--alternative <ref>] [--docs <url>] \
#                     [--push --confirm <name>:<tag>]
#
# Example (dry run):
#   eol/retire-tag.sh --image python-base --tag v1.1 \
#     --replacement ghcr.io/interrzero/base-docker-images/python-3.13-base:latest \
#     --reason "python-base was renamed to python-3.13-base and is no longer built."
#
# Pushing requires `docker login ghcr.io` with a token carrying write:packages.
# REGISTRY_REPO can be overridden to rehearse against a throwaway registry.
set -euo pipefail

image="" tag="" replacement="" alternative="" reason="" docs="" push=0 confirm=""

while [ $# -gt 0 ]; do
  case "$1" in
    --image)       image="${2:?}"; shift 2 ;;
    --tag)         tag="${2:?}"; shift 2 ;;
    --replacement) replacement="${2:?}"; shift 2 ;;
    --alternative) alternative="${2:?}"; shift 2 ;;
    --reason)      reason="${2:?}"; shift 2 ;;
    --docs)        docs="${2:?}"; shift 2 ;;
    --confirm)     confirm="${2:?}"; shift 2 ;;
    --push)        push=1; shift ;;
    -h|--help)     sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for required in image tag replacement reason; do
  if [ -z "${!required}" ]; then
    echo "missing --${required} (see --help)" >&2
    exit 2
  fi
done

repo="${REGISTRY_REPO:-ghcr.io/interrzero/base-docker-images}"
pkg_url="https://github.com/interrzero/base-docker-images/pkgs/container/base-docker-images%2F${image}"
docs_url="${docs:-https://github.com/interrzero/base-docker-images#readme}"
context="$(cd "$(dirname "$0")" && pwd)"

# The confirmation has to name the exact image and tag. A bare --push would
# make a typo in --tag silently retire the wrong thing.
if [ "$push" -eq 1 ] && [ "$confirm" != "${image}:${tag}" ]; then
  echo "refusing to push: --confirm must be exactly '${image}:${tag}'" >&2
  echo "  (this is the per-tag approval gate; see the header of this script)" >&2
  exit 2
fi

build_marker() {
  local platforms="$1" suffix="$2" action="$3"
  docker buildx build --pull "$action" \
    --platform "$platforms" \
    --tag "${repo}/${image}${suffix}:${tag}" \
    --build-arg RETIRED_REF="${repo}/${image}${suffix}:${tag}" \
    --build-arg REPLACEMENT_REF="${replacement}" \
    --build-arg ALTERNATIVE_REF="${alternative}" \
    --build-arg PACKAGE_URL="${pkg_url}${suffix}" \
    --build-arg DOCS_URL="${docs_url}" \
    --build-arg EOL_REASON="${reason}" \
    "$context"
}

is_eol_marker() {
  docker buildx imagetools inspect "$1" --format '{{json .Image}}' 2>/dev/null |
    jq -e '[.. | objects | .Labels? // empty
           | .["io.interruptzero.base-docker-images.eol-marker"]?] | any(. == "true")' \
    > /dev/null 2>&1
}

if [ "$push" -eq 0 ]; then
  echo "DRY RUN. Nothing is pushed. These tags WOULD be overwritten:"
  for suffix in "" "-linux-amd64" "-linux-arm64"; do
    echo "  ${repo}/${image}${suffix}:${tag}"
  done
  echo
  echo "Replacement named in the marker: ${replacement}"
  [ -n "$alternative" ] && echo "Alternative named in the marker:  ${alternative}"
  echo "Reason: ${reason}"
  echo
  echo "Building the marker locally to prove it compiles (not pushed)..."
  build_marker "linux/amd64" "" "--load"
  echo
  echo "To retire for real, re-run with: --push --confirm ${image}:${tag}"
  exit 0
fi

build_marker "linux/amd64,linux/arm64" "" "--push"
build_marker "linux/amd64" "-linux-amd64" "--push"
build_marker "linux/arm64" "-linux-arm64" "--push"

failed=0
for suffix in "" "-linux-amd64" "-linux-arm64"; do
  ref="${repo}/${image}${suffix}:${tag}"
  if is_eol_marker "$ref"; then
    echo "[ok] ${ref} is now the end-of-life marker"
  else
    echo "[fail] ${ref} is not the end-of-life marker" >&2
    failed=1
  fi
done
exit "$failed"
