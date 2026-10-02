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

# Third surface: what is INSIDE each seed wheel.
#
# The checks above only compare seed wheels against each other, so a single
# wheel with no duplicate passes even when the code inside it is vulnerable.
# That is exactly what happened: virtualenv 21.14.5 bundles a pip 26.2.1 seed
# wheel vendoring urllib3 2.7.0, while the ensurepip wheel Chainguard ships at
# /usr/share/python-wheels carries the patched 2.8.0. Every environment made by
# "virtualenv" or by poetry - which creates its environments through virtualenv
# - gets the 2.7.0 copy. Measured, not assumed.
#
# No scanner here catches it. Trivy does not read inside .whl files, so the
# image scans clean while shipping the vulnerable code.
#
# The reference is the distro wheel of the SAME pip version rather than a list
# of package names and floors. Chainguard patches that wheel, so the assertion
# is "the seed wheel must not be behind the wheel we actually trust", and a
# future patch is picked up with no edit here. Only packages present in both
# are compared, and only a seed version strictly older than the reference is a
# finding - a seed wheel ahead of the reference is not.
echo "  checking seed wheel interiors against the distro wheel"
interior="$(docker run --rm --platform "${PLATFORM}" --entrypoint python3 "${IMAGE}" -c '
import glob, io, re, sys, zipfile

def pins(zf, prefix):
    """name -> version from <dist>/_vendor/vendor.txt inside a wheel."""
    out = {}
    for n in zf.namelist():
        if n.endswith("_vendor/vendor.txt") and n.startswith(prefix + "/"):
            for raw in zf.read(n).decode("utf8", "ignore").splitlines():
                line = raw.split("#", 1)[0].strip()
                m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,]+)", line)
                if m:
                    out[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(2)
    return out

def parse(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])

# Scoped to real site-packages roots. A recursive glob from / walks /proc and
# /sys and does not finish inside the step timeout.
import site
roots = set(site.getsitepackages() or [])
try:
    roots.add(site.getusersitepackages())
except Exception:
    pass
roots.update(glob.glob("/usr/lib/python3*/site-packages"))
roots.update(glob.glob("/home/*/.local/lib/python3*/site-packages"))
# Deduplicate by real path: the roots above overlap (site.getsitepackages()
# and the explicit globs can name the same directory), and without this each
# finding is reported more than once.
import os
seeds = sorted(
    {
        os.path.realpath(w)
        for r in roots
        for w in glob.glob(r + "/virtualenv/seed/wheels/embed/*.whl")
    }
)
if not seeds:
    print("SKIP no virtualenv seed wheels")
    sys.exit(0)

problems = 0
compared = 0
for seed in seeds:
    base = seed.rsplit("/", 1)[-1]
    dist = base.split("-", 1)[0]
    refs = glob.glob("/usr/share/python-wheels/" + base)
    if not refs:
        print("NOREF %s has no distro wheel of the same version to compare against" % base)
        continue
    try:
        sp = pins(zipfile.ZipFile(seed), dist)
        rp = pins(zipfile.ZipFile(refs[0]), dist)
    except Exception as e:
        print("UNREADABLE %s: %s" % (base, e))
        problems += 1
        continue
    for name, sv in sorted(sp.items()):
        rv = rp.get(name)
        if rv is None:
            continue
        compared += 1
        try:
            behind = parse(sv) < parse(rv)
        except Exception:
            behind = sv != rv
        if behind:
            print("BEHIND %s vendors %s %s but the distro wheel has %s" % (base, name, sv, rv))
            problems += 1
print("COMPARED %d" % compared)
print("DONE %d" % problems)
' 2>&1)" || {
  echo "::error::check-virtualenv-seeds: seed wheel interior check failed to run" >&2
  printf '  %s\n' "${interior//$'\n'/$'\n'  }" >&2
  exit 1
}

printf '  %s\n' "${interior//$'\n'/$'\n'  }"

if ! echo "${interior}" | grep -qE '^(SKIP|DONE) '; then
  echo "::error::seed wheel interior check did not complete; refusing to report clean" >&2
  exit 1
fi

if echo "${interior}" | grep -q '^BEHIND '; then
  echo "::error::a virtualenv seed wheel vendors a dependency older than the distro wheel of the same version. Every environment created from it inherits that code, and no scanner reads inside a .whl." >&2
  exit 1
fi
if echo "${interior}" | grep -qE '^(UNREADABLE) '; then
  echo "::error::a virtualenv seed wheel could not be read; refusing to report clean" >&2
  exit 1
fi

echo "check-virtualenv-seeds: ok - one seed wheel per project, inventory agrees, interiors not behind the distro wheel"
