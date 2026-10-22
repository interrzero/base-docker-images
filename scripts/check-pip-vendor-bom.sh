#!/usr/bin/env bash
# Fail if pip's bundled CycloneDX BOM disagrees with what pip actually vendors.
#
# pip ships bom.cdx.json describing its vendored dependencies, and scanners read
# it as the inventory of installed software. It can disagree with the code pip
# actually bundles, in either direction: measured on pip 26.2.1, the BOM
# declared urllib3 2.7.0 while 2.8.0 was installed, and idna 3.18 while 3.15 was
# installed. The first blocked every python image publish for two days against a
# vulnerability that was not present; the second would have masked a real finding
# in 3.15 by claiming a newer version.
#
# A stale declaration is invisible to every other gate here: the finding it
# produces carries no file path, so there is nothing on disk to inspect, and the
# Trivy step cannot tell a misdeclaration from a real vulnerability.
#
# harden-pip-vendor.py reconciles the BOM against vendor.txt at build time. This
# is the gate that stops a regression being published if that step is dropped,
# reordered, or silently fails. It runs against the built image rather than the
# Dockerfile meant to produce it.
#
# Images without pip's vendored BOM pass trivially.
#
# Usage: check-pip-vendor-bom.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-pip-vendor-bom.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-pip-vendor-bom.sh <image-ref> <platform>}"

echo "check-pip-vendor-bom: ${IMAGE} (${PLATFORM})"

# Probe for an interpreter before trying to run one. The publish workflow calls
# this for every image, and most of them have no python at all - treating a
# missing interpreter as a failure would red-light the whole fleet. An image
# without python cannot carry pip's vendored BOM, so this is a genuine pass.
#
# The probe's exit status decides, not just its success: docker exits 125 when
# it cannot run the image at all - a missing image, a platform the image was
# not built for, a daemon error - and 126/127 when the command is not in the
# image. Only the second is "no python3"; the first used to read as a pass.
probe_rc=0
docker run --rm --platform "${PLATFORM}" --entrypoint sh "${IMAGE}" \
  -c 'command -v python3 >/dev/null 2>&1' 2>/dev/null || probe_rc=$?
case "${probe_rc}" in
  0) ;;
  1|126|127)
    echo "  no python3 in this image - no pip vendored BOM to check"
    exit 0
    ;;
  *)
    echo "::error::could not run ${IMAGE} for ${PLATFORM} (docker exit ${probe_rc}); refusing to report clean" >&2
    exit 1
    ;;
esac

# The comparison runs inside the image, in python, because that is the only way
# to read the importable module's own __version__ rather than trusting a
# declaration. Python is guaranteed present in any image that has pip. It runs
# isolated (-I), so nothing on the image PYTHONPATH can shadow what it imports.
report="$(docker run --rm --platform "${PLATFORM}" --entrypoint python3 "${IMAGE}" -I -c '
import json, pathlib, re, sys

def normalize(name):
    return re.sub(r"[-_.]+", "-", name).strip().lower()

roots = list(pathlib.Path("/").glob("**/site-packages/pip/_vendor"))
roots = [r for r in roots if (r / "bom.cdx.json").is_file()]
if not roots:
    print("SKIP no pip vendored BOM present")
    sys.exit(0)

problems = []
for vendor in roots:
    pins = {}
    vt = vendor / "vendor.txt"
    if not vt.is_file():
        problems.append("MISSING %s" % vt)
        continue
    for raw in vt.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,]+)", line)
        if m:
            pins[normalize(m.group(1))] = m.group(2)
    if not pins:
        problems.append("UNPARSEABLE %s" % vt)
        continue
    try:
        bom = json.loads((vendor / "bom.cdx.json").read_text())
    except Exception as e:
        problems.append("UNPARSEABLE bom.cdx.json: %s" % e)
        continue
    comps = bom.get("components")
    if not isinstance(comps, list):
        problems.append("bom.cdx.json has no components list")
        continue
    checked = 0
    for c in comps:
        name = str(c.get("name", ""))
        declared = str(c.get("version", ""))
        pinned = pins.get(normalize(name))
        if pinned is None:
            continue
        checked += 1
        if declared != pinned:
            problems.append(
                "%s declared %s in bom.cdx.json but vendor.txt pins %s"
                % (name, declared, pinned)
            )
    if checked == 0:
        problems.append("no bom.cdx.json component matched any vendor.txt pin")
    # A dependency on a component the BOM does not declare describes a package
    # that is not there: what a removal leaves behind if it drops only the
    # component (pkg_resources once left its setuptools node and edge).
    known = {c.get("bom-ref") for c in comps}
    known.add(((bom.get("metadata") or {}).get("component") or {}).get("bom-ref"))
    for entry in bom.get("dependencies") or []:
        for ref in [entry.get("ref")] + list(entry.get("dependsOn") or []):
            if ref not in known:
                problems.append("bom.cdx.json depends on %s, which no component declares" % ref)
    print("CHECKED %d components under %s" % (checked, vendor))

for p in problems:
    print("PROBLEM %s" % p)
print("DONE %d" % len(problems))
' 2>&1)" || {
  echo "::error::check-pip-vendor-bom: the in-image comparison failed to run" >&2
  printf '%s\n' "${report//$'\n'/$'\n'  }" >&2
  exit 1
}

printf '  %s\n' "${report//$'\n'/$'\n'  }"

if echo "${report}" | grep -q '^SKIP '; then
  exit 0
fi

# Absence of a DONE line means the comparison did not finish. Treating that as
# a pass would report a broken check as a clean image.
if ! echo "${report}" | grep -q '^DONE '; then
  echo "::error::check-pip-vendor-bom: comparison did not complete; refusing to report clean" >&2
  exit 1
fi

count="$(echo "${report}" | sed -n 's/^DONE \([0-9]*\)$/\1/p' | tail -n1)"
if [ "${count:-1}" -ne 0 ]; then
  echo "::error::pip's bom.cdx.json disagrees with vendor.txt or depends on a component it does not declare. harden-pip-vendor.py should have reconciled it." >&2
  exit 1
fi

echo "check-pip-vendor-bom: ok - every declared component agrees with vendor.txt"
