#!/usr/bin/env bash
# Fail if a built image ships an apk package older than the repository offers.
#
# WHY THIS EXISTS, given we already scan with Trivy.
#
# A vulnerability scanner can only report what its database knows. Ours has
# repeatedly been blind to real content: it does not index the Go toolchain, so
# go1.25.12 shipped unreported; it does not index npm's bundled node_modules; and
# it did not index virtualenv's seed wheels until those were removed by hand. In
# each case a downstream consumer's scanner saw findings that ours reported as
# zero. An image can therefore be genuinely stale while every gate we run says
# clean.
#
# This check asks a different question, one that needs no CVE database at all:
# is anything installed here older than what the repository currently offers?
# "apk version -l <" answers exactly that, and it is the right primitive because
# apk understands its own version grammar - including Wolfi's version-streamed
# package names such as glibc-2.44 and openssl-4.0-libcrypto, where a naive
# string or sort -V comparison picks the wrong winner.
#
# Self-healing by construction:
#   - nothing is pinned, and no package list is maintained here. The comparison
#     is against the live repository at build time, so a new release is picked up
#     with no edit to this file.
#   - it cannot drift. A package added to an image in future is covered the day
#     it is added, because the check enumerates what is installed rather than
#     consulting a list someone has to remember to update.
#   - it fails closed. An image whose packages cannot be enumerated is an
#     unknown, not a pass.
#
# It is deliberately NOT a vulnerability check. Being current is not the same as
# being free of vulnerabilities - go1.25.12 is current and still carries stdlib
# advisories fixed only in 1.25.13, which does not exist yet anywhere. This
# guard's claim is narrower and checkable: we are not behind.
#
# Images without apk (distroless final stages, e.g. nginx-base) pass trivially.
#
# Usage: check-package-freshness.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-package-freshness.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-package-freshness.sh <image-ref> <platform>}"

echo "check-package-freshness: ${IMAGE} (${PLATFORM})"

# --user root: these images run as nonroot, and apk cannot write its index
# cache without write access. Without this "apk update" exits 99 and
# "apk version" silently compares against the index baked into the image
# instead of the live repository - which reports everything as current no
# matter how stale it is. That false green is the exact failure this guard
# exists to prevent, so it must not be the guard's own behaviour.
if ! docker run --rm --platform "${PLATFORM}" --user root --entrypoint sh "${IMAGE}" -c 'command -v apk' >/dev/null 2>&1; then
  echo "  no apk in this image - nothing to compare"
  exit 0
fi

stale="$(docker run --rm --platform "${PLATFORM}" --user root --entrypoint sh "${IMAGE}" -c '
  apk update >/dev/null 2>&1 || exit 97
  apk version -l "<" 2>/dev/null | tail -n +2
' 2>/dev/null)" || {
  echo "::error::could not refresh the package index inside ${IMAGE}; freshness is UNKNOWN, not clean" >&2
  exit 1
}

if [ -z "${stale}" ]; then
  echo "  every installed package is at the newest version the repository offers"
  exit 0
fi

echo "::error::${IMAGE} ships packages older than the repository offers:" >&2
echo "${stale}" | sed 's/^/    /' >&2
echo "::error::rebuild picks these up automatically - if this persists, the image's apk upgrade step is not working." >&2
exit 1
