#!/usr/bin/env bash
# Fail if a distro package's SPDX SBOM declares a version the image does not have.
#
# Wolfi ships an SPDX document per apk under /var/lib/db/sbom, and those
# documents enumerate the dependencies VENDORED inside the package - npm's
# node_modules tree, a python package's bundled deps. Scanners read them as the
# inventory of installed software, so an entry that disagrees with the file it
# claims to describe is reported to consumers as a vulnerability that is not
# there, or hides one that is.
#
# Third surface of the same failure in one week: npm's apk SBOM declaring
# superseded vendored versions, virtualenv's seed wheels, and pip's own
# bom.cdx.json. The first two have guards; this is the one that did not.
#
# Each package entry states where its information came from, e.g.
#   "acquired package info from installed node module manifest file: usr/..."
# so the check compares against the very file the SBOM names. That makes it
# generic: no package list, no version floors, correct as the distro changes.
# Entries naming no manifest (the apk's own record, cargo manifests) are
# counted and skipped rather than guessed at, so coverage is visible.
#
# The image filesystem is exported and read on the host rather than running an
# interpreter inside it. An earlier version shelled into the image and needed
# python3, which silently skipped every nodejs image - no interpreter, so no
# check, reported as a pass. Exporting works for distroless images too.
#
# Usage: check-apk-sbom-disk.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-apk-sbom-disk.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-apk-sbom-disk.sh <image-ref> <platform>}"

echo "check-apk-sbom-disk: ${IMAGE} (${PLATFORM})"

# A command argument is required even though the container is never started:
# "docker create" refuses an image that declares neither CMD nor ENTRYPOINT
# with "no command specified". The FIPS images are exactly that - their only
# CMD belongs to a HEALTHCHECK - so without this the guard failed to create a
# container and blocked their publish outright. The placeholder is never
# executed and does not need to exist in the image.
cid="$(docker create --platform "${PLATFORM}" "${IMAGE}" true 2>&1)" || {
  echo "::error::could not create a container from ${IMAGE}: ${cid}" >&2
  exit 1
}
trap 'docker rm -f "${cid}" >/dev/null 2>&1 || true' EXIT

report="$(docker export "${cid}" 2>/dev/null | python3 -c '
import io, json, re, sys, tarfile

NODE = re.compile(r"installed node module manifest file:\s*(\S+)")
PY   = re.compile(r"installed python package manifest file:\s*(\S+)")

sboms = {}
versions = {}

def norm(name):
    return name.lstrip("./").lstrip("/")

with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as tar:
    for member in tar:
        if not member.isfile():
            continue
        name = norm(member.name)
        if name.startswith("var/lib/db/sbom/") and name.endswith(".spdx.json"):
            try:
                sboms[name] = json.loads(tar.extractfile(member).read().decode("utf8", "ignore"))
            except Exception as exc:
                sboms[name] = {"__error__": str(exc)}
        elif name.endswith("/package.json"):
            try:
                versions[name] = json.loads(
                    tar.extractfile(member).read().decode("utf8", "ignore")).get("version")
            except Exception:
                pass
        elif name.endswith(".whl"):
            # A distro SBOM can name a wheel rather than a manifest, e.g.
            # py3-pip-wheel points at usr/share/python-wheels/pip-<v>.whl.
            # PEP 427 puts the version in the file name as the second
            # hyphen-separated field, so it is read from there.
            parts = name.rsplit("/", 1)[-1][:-4].split("-")
            if len(parts) >= 2:
                versions[name] = parts[1]
        elif name.endswith("/METADATA") and ".dist-info/" in name:
            try:
                for line in tar.extractfile(member).read().decode("utf8", "ignore").splitlines():
                    if line.startswith("Version:"):
                        versions[name] = line.split(":", 1)[1].strip()
                        break
            except Exception:
                pass

if not sboms:
    print("SKIP no /var/lib/db/sbom documents in this image")
    sys.exit(0)

checked = skipped = unresolved = 0
problems = []
for doc_name, doc in sorted(sboms.items()):
    if "__error__" in doc:
        problems.append("UNPARSEABLE %s: %s" % (doc_name.split("/")[-1], doc["__error__"]))
        continue
    for pkg in doc.get("packages", []):
        src = pkg.get("sourceInfo") or ""
        m = NODE.search(src) or PY.search(src)
        if not m:
            skipped += 1
            continue
        path = norm(m.group(1))
        actual = versions.get(path)
        if actual is None:
            unresolved += 1
            continue
        checked += 1
        declared = str(pkg.get("versionInfo", ""))
        if declared != actual:
            problems.append("MISMATCH %s: %s declares %s but %s is %s"
                            % (doc_name.split("/")[-1], pkg.get("name"), declared, path, actual))

for p in problems:
    print(p)
print("CHECKED %d  SKIPPED(names no manifest) %d  UNRESOLVED(file absent) %d"
      % (checked, skipped, unresolved))
print("DONE %d" % len(problems))
' 2>&1)" || {
  echo "::error::check-apk-sbom-disk: the comparison failed to run" >&2
  printf '  %s\n' "${report//$'\n'/$'\n'  }" >&2
  exit 1
}

printf '  %s\n' "${report//$'\n'/$'\n'  }"

if echo "${report}" | grep -q '^SKIP '; then
  exit 0
fi

# No DONE line means the comparison did not finish. Reporting that as a pass
# would turn a broken check into a clean bill of health.
if ! echo "${report}" | grep -q '^DONE '; then
  echo "::error::check-apk-sbom-disk: comparison did not complete; refusing to report clean" >&2
  exit 1
fi

count="$(echo "${report}" | sed -n 's/^DONE \([0-9]*\)$/\1/p' | tail -n1)"
if [ "${count:-1}" -ne 0 ]; then
  echo "::error::a distro SBOM declares a version the image does not contain. Scanners read these as the installed inventory, so this is reported to consumers as fact." >&2
  exit 1
fi

checked="$(echo "${report}" | sed -n 's/^CHECKED \([0-9]*\).*/\1/p' | tail -n1)"
if [ "${checked:-0}" -eq 0 ]; then
  # Not a failure: plenty of images declare nothing resolvable. Said plainly so
  # the line is never mistaken for "this image was verified".
  echo "check-apk-sbom-disk: no resolvable SBOM entries in this image - nothing was verified"
else
  echo "check-apk-sbom-disk: ok - ${checked} SBOM entries agree with the files they name"
fi
