#!/usr/bin/env bash
# Print the repository paths an image's published content depends on.
#
# An image was previously rebuilt only when its own Dockerfile changed. That is
# wrong whenever the Dockerfile COPYs something: a fix landing in a copied
# script changes what the image contains, but not the Dockerfile, so no tag was
# cut and the fix sat unpublished. That happened for real - the pip BOM
# reconcile in scripts/harden-pip-vendor.py was merged and then went unshipped
# until someone triggered a build by hand, while downstream consumers' required
# scans stayed red against the stale image.
#
# The set is DERIVED from the Dockerfile rather than hand-maintained, so a new
# COPY is covered the day it is added and nobody has to remember a list.
#
# Modes:
#   inputs <image>          paths that image depends on, one per line
#   shared                  paths that affect EVERY image
#   affected <from> <to>    image names whose inputs changed in that range
#
# Usage: image-build-inputs.sh inputs python-3.13-base
set -euo pipefail

# Inputs that decide whether ANY image may publish, so a change to one of them
# has to rebuild the fleet rather than silently apply to whatever builds next.
shared_inputs() {
  cat <<'SHARED'
trivy.yaml
.trivyignore.yaml
.github/workflows/publish-base-images.yml
SHARED
  # Gate scripts run against every built image before it is pushed, so a change
  # to one of them changes whether an image is publishable.
  find scripts -maxdepth 1 -name 'check-*.sh' 2>/dev/null | sort
}

# Local sources a Dockerfile COPYs or ADDs. "--from=" stages are intentionally
# excluded: those come from an earlier stage, not from the repository.
dockerfile_sources() {
  local dockerfile="$1"
  [ -f "$dockerfile" ] || return 0
  awk '
    toupper($1) == "COPY" || toupper($1) == "ADD" {
      from_stage = 0
      n = 0
      for (i = 2; i <= NF; i++) {
        if ($i ~ /^--from=/) { from_stage = 1; continue }
        if ($i ~ /^--/) { continue }
        n++; tok[n] = $i
      }
      # The last token is the destination inside the image, never a repo path.
      if (!from_stage && n >= 2) {
        for (i = 1; i < n; i++) print tok[i]
      }
    }
  ' "$dockerfile" | sed 's#^\./##' | sort -u
}

image_inputs() {
  local image="$1"
  echo "Dockerfile.${image}"
  dockerfile_sources "Dockerfile.${image}"
  local cst="tests/container-structure/${image}.yaml"
  [ -f "$cst" ] && echo "$cst"
  return 0
}

all_images() {
  find . -maxdepth 1 -name 'Dockerfile.*' ! -name 'deprecated.Dockerfile.*' \
    | sed 's#^\./Dockerfile\.##' | sort
}

case "${1:-}" in
  inputs)
    image_inputs "${2:?usage: image-build-inputs.sh inputs <image>}" | sort -u
    ;;
  shared)
    shared_inputs | sort -u
    ;;
  owners)
    # Which images depend on one path? The inverse of "inputs", used by the tag
    # workflow on a pull request: there the question is "what does THIS PR
    # touch", and comparing against release tags answers a different question
    # and selects nearly every image, because main moves between releases.
    path="${2:?usage: image-build-inputs.sh owners <path>}"
    path="${path#./}"
    matched=0
    while read -r s_path; do
      [ -n "$s_path" ] || continue
      if [ "$s_path" = "$path" ]; then
        # A shared input changes whether ANY image may publish, so it owns all.
        all_images
        exit 0
      fi
    done < <(shared_inputs)
    while read -r image; do
      [ -n "$image" ] || continue
      while read -r in_path; do
        [ -n "$in_path" ] || continue
        if [ "$in_path" = "$path" ]; then
          echo "$image"
          matched=1
          break
        fi
      done < <(image_inputs "$image")
    done < <(all_images)
    # A path owned by no image (README, docs) prints nothing and exits 0: that
    # is "no image needs rebuilding", not an error.
    [ "$matched" -ge 0 ] || true
    ;;
  affected)
    from="${2:?usage: image-build-inputs.sh affected <from> <to>}"
    to="${3:?usage: image-build-inputs.sh affected <from> <to>}"
    changed="$(git diff --name-only "$from" "$to")"
    # A shared input changing means every image's publishability changed.
    while read -r s; do
      [ -n "$s" ] || continue
      if printf '%s\n' "$changed" | grep -qxF "$s"; then
        all_images
        exit 0
      fi
    done < <(shared_inputs)
    while read -r image; do
      [ -n "$image" ] || continue
      while read -r path; do
        [ -n "$path" ] || continue
        if printf '%s\n' "$changed" | grep -qxF "$path"; then
          echo "$image"
          break
        fi
      done < <(image_inputs "$image")
    done < <(all_images)
    ;;
  *)
    echo "usage: $0 {inputs <image>|shared|owners <path>|affected <from> <to>}" >&2
    exit 2
    ;;
esac
