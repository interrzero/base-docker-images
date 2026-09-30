#!/usr/bin/env bash
# Fail if a built image carries a superseded virtualenv seed wheel.
#
# virtualenv bundles one pip/setuptools pair per supported Python version under
# virtualenv/seed/wheels/embed. Only the highest version of each project can be
# used by an image that ships a single Python, so any lower version present is
# dead weight carrying its original CVEs. harden-virtualenv-seeds.py removes
# them at build time; this is the gate that stops a regression being published
# if that step is ever dropped, reordered, or silently fails.
#
# Runs against the built image before it is pushed, so the check is on the
# artifact rather than on the Dockerfile that was meant to produce it.
#
# Images with no seed wheels pass trivially - most images here do not install
# virtualenv, and their absence is not a finding.
#
# Usage: check-virtualenv-seeds.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"

echo "check-virtualenv-seeds: ${IMAGE} (${PLATFORM})"

# List seed wheels by filename. A shell is required, which every image carrying
# virtualenv has; an image without one also has no seed wheels to check.
wheels="$(docker run --rm --platform "${PLATFORM}" --entrypoint sh "${IMAGE}" -c \
  'find / -path "*/virtualenv/seed/wheels/embed/*.whl" 2>/dev/null | sed "s|.*/||" | sort' 2>/dev/null || true)"

if [ -z "${wheels}" ]; then
  echo "  no virtualenv seed wheels present - nothing to check"
  exit 0
fi

echo "  seed wheels found:"
echo "${wheels}" | sed 's/^/    /'

# Group by project and assert exactly one version each, and that it is the
# highest. sort -V is version-aware, so 26.10 ranks above 26.2.
violations=0
projects="$(echo "${wheels}" | sed -E 's/^([A-Za-z0-9_.+-]+)-[0-9].*$/\1/' | sort -u)"
for project in ${projects}; do
  versions="$(echo "${wheels}" | grep -E "^${project}-[0-9]" \
              | sed -E "s/^${project}-([^-]+)-.*$/\1/" | sort -V)"
  count="$(echo "${versions}" | grep -c . || true)"
  highest="$(echo "${versions}" | tail -n1)"
  if [ "${count}" -gt 1 ]; then
    echo "::error::${project} has ${count} seed wheels; only the highest (${highest}) may remain."
    echo "${versions}" | sed 's/^/      present: /'
    violations=$((violations + 1))
  else
    echo "  ${project}: ${highest} only - ok"
  fi
done

if [ "${violations}" -ne 0 ]; then
  echo "::error::${violations} project(s) carry a superseded seed wheel. harden-virtualenv-seeds.py should have removed them." >&2
  exit 1
fi

# Second surface: the declared inventory. Deleting the files but leaving the
# SBOM or RECORD describing them would misreport the image, and is what makes
# the finding appear with no file path.
stale="$(docker run --rm --platform "${PLATFORM}" --entrypoint sh "${IMAGE}" -c '
  for d in $(find / -type d -name "virtualenv-*.dist-info" 2>/dev/null); do
    for f in "$d"/RECORD "$d"/sboms/*.json; do
      [ -f "$f" ] || continue
      grep -oE "(pip|setuptools)-[0-9][^\"/,[:space:]]*" "$f" 2>/dev/null
    done
  done | sort -u' 2>/dev/null || true)"

if [ -n "${stale}" ]; then
  echo "  inventory references:"
  echo "${stale}" | sed 's/^/    /'
  for project in ${projects}; do
    kept="$(echo "${wheels}" | grep -E "^${project}-[0-9]" | sed -E "s/^${project}-([^-]+)-.*$/\1/" | sort -V | tail -n1)"
    bad="$(echo "${stale}" | grep -E "^${project}-" | grep -v -E "^${project}-${kept}([^0-9]|$)" || true)"
    if [ -n "${bad}" ]; then
      echo "::error::inventory still declares ${project} versions that are not on disk:" >&2
      echo "${bad}" | sed 's/^/      /' >&2
      violations=$((violations + 1))
    fi
  done
fi

if [ "${violations}" -ne 0 ]; then
  exit 1
fi

echo "check-virtualenv-seeds: ok - one seed wheel per project, inventory agrees"
