#!/usr/bin/env bash
# Fail if a built image carries a vendored npm dependency below its fix floor.
#
# npm ships a node_modules tree of its own dependencies inside the package, and
# scanners read those package.json files as an inventory. harden-node-vendor.js
# raises the ones with known advisories at build time; this is the gate that
# stops a regression being published if that step is ever dropped, reordered, or
# silently fails.
#
# Runs against the built image before it is pushed, so the check is on the
# artifact rather than on the Dockerfile that was meant to produce it. Our own
# scanners do not index this tree at all - trivy and grype both return zero
# against it - so without this gate nothing would notice.
#
# The floors are read out of harden-node-vendor.js rather than repeated here.
# Two copies of the list would drift, and the copy in the guard drifting is the
# worse direction: it would pass while the image regressed.
#
# Images without npm pass trivially.
#
# Usage: check-node-vendor.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-node-vendor.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-node-vendor.sh <image-ref> <platform>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARDEN_SCRIPT="${SCRIPT_DIR}/harden-node-vendor.js"

echo "check-node-vendor: ${IMAGE} (${PLATFORM})"

if [ ! -f "${HARDEN_SCRIPT}" ]; then
  echo "::error::${HARDEN_SCRIPT} not found; cannot determine fix floors." >&2
  exit 1
fi

# Extract "name version" pairs from the TARGETS object. Restricted to the lines
# between the declaration and its closing brace so a quoted string elsewhere in
# the file cannot be mistaken for a target.
targets="$(sed -n "/^const TARGETS = {/,/^};/p" "${HARDEN_SCRIPT}" \
           | sed -nE "s/^[[:space:]]*'([^']+)':[[:space:]]*'([^']+)'.*$/\1 \2/p")"

if [ -z "${targets}" ]; then
  echo "::error::no targets parsed from ${HARDEN_SCRIPT}; the guard would pass vacuously." >&2
  exit 1
fi

echo "  fix floors declared in harden-node-vendor.js:"
while read -r _n _v; do echo "    ${_n} ${_v}"; done <<< "${targets}"

# Locate npm's vendored tree. A shell is required, which every image shipping
# npm has; an image without one also has no vendored tree to check.
vendor_dir="$(docker run --rm --platform "${PLATFORM}" --entrypoint sh "${IMAGE}" -c \
  'find / -type d -path "*/node_modules/npm/node_modules" 2>/dev/null | head -n1' 2>/dev/null || true)"

if [ -z "${vendor_dir}" ]; then
  echo "  no npm vendored tree present - nothing to check"
  exit 0
fi
echo "  vendored tree: ${vendor_dir}"

violations=0
while read -r name floor; do
  [ -n "${name}" ] || continue

  actual="$(docker run --rm --platform "${PLATFORM}" --entrypoint sh "${IMAGE}" -c \
    "cat '${vendor_dir}/${name}/package.json' 2>/dev/null" 2>/dev/null \
    | sed -nE 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"

  if [ -z "${actual}" ]; then
    # Not an image defect: npm may have stopped vendoring it. But the target
    # list is then stale, and staleness must be corrected rather than tolerated
    # here, because a silent skip is indistinguishable from a passing check.
    echo "::error::${name} is not vendored in this image; the target list in harden-node-vendor.js is stale." >&2
    violations=$((violations + 1))
    continue
  fi

  # sort -V is version-aware: 5.0.12 ranks above 5.0.11, which a string
  # comparison would get backwards.
  lowest="$(printf '%s\n%s\n' "${actual}" "${floor}" | sort -V | head -n1)"
  if [ "${actual}" != "${floor}" ] && [ "${lowest}" = "${actual}" ]; then
    echo "::error::${name} is ${actual}, below the ${floor} fix floor. harden-node-vendor.js should have raised it." >&2
    violations=$((violations + 1))
  else
    echo "  ${name}: ${actual} (floor ${floor}) - ok"
  fi
done <<< "${targets}"

if [ "${violations}" -ne 0 ]; then
  echo "::error::${violations} vendored package(s) failed the fix-floor check." >&2
  exit 1
fi

# Second surface: npm must still work. Replacing a member of the vendored tree
# can break npm even when every version is individually in range - that is how
# the sweep this replaced was caught, and `npm view` was the only command that
# revealed it. Asserting versions without asserting function would have passed
# that broken image.
#
# --cache is required, not incidental. These images run as a nonroot user whose
# HOME is not writable, so npm's default cache location fails with EACCES and
# every command that touches the cache exits nonzero. Without this the guard
# red-lights a perfectly good image, which is worse than having no guard: the
# first response to a false red is to weaken the check. Verified both ways on
# the same image - as root it passes, as nonroot without --cache it does not.
echo "  exercising npm"
npm_out="$(docker run --rm --platform "${PLATFORM}" --entrypoint sh "${IMAGE}" -c \
  'npm --version >/dev/null 2>&1 || { echo "npm --version failed"; exit 1; }
   npm help >/dev/null 2>&1 || { echo "npm help failed"; exit 1; }
   npm --cache /tmp/npm-guard-cache view semver version >/dev/null 2>&1 || { echo "npm view failed"; exit 1; }
   echo ok' 2>&1)" || true

if [ "${npm_out##*$'\n'}" != "ok" ]; then
  echo "::error::npm is not functional after vendor hardening: ${npm_out}" >&2
  exit 1
fi
echo "  npm --version, help and view all ok"

echo "check-node-vendor: ok - every target at or above its fix floor, npm functional"
