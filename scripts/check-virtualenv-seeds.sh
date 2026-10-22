#!/usr/bin/env bash
# Fail if a built image carries a superseded, misdeclared or under-hardened
# virtualenv seed wheel, or an ensurepip wheel that vendors what the installed
# pip was hardened to drop.
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
# Images with no seed wheels and no ensurepip wheels pass - most images here do
# not install python - but only once the image's filesystem has actually been
# read. An image that cannot be created or exported for the requested platform
# fails: "could not look" is never reported as "nothing there".
#
# Usage: check-virtualenv-seeds.sh <image-ref> <platform>
set -euo pipefail

IMAGE="${1:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"
PLATFORM="${2:?usage: check-virtualenv-seeds.sh <image-ref> <platform>}"

echo "check-virtualenv-seeds: ${IMAGE} (${PLATFORM})"

# What harden-pip-vendor.py removes from pip's vendored tree, read from that
# script rather than restated here, so the gate and the hardening cannot drift.
policy="$(python3 -I - "$(dirname "${BASH_SOURCE[0]}")/harden-pip-vendor.py" <<'PY'
import ast, json, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "REMOVED_VENDORED"
        for target in node.targets
    ):
        value = ast.literal_eval(node.value)
        if isinstance(value, dict) and value:
            print(json.dumps(value, sort_keys=True))
            sys.exit(0)
sys.exit("REMOVED_VENDORED not found, or empty")
PY
)" || {
  echo "::error::check-virtualenv-seeds: cannot read REMOVED_VENDORED from harden-pip-vendor.py" >&2
  exit 1
}

# First surface: which wheels exist, read from the exported filesystem on the
# host. This works for every image, with or without a shell, and anything that
# stops the image being created or exported - a missing image, a platform the
# image was not built for - fails here instead of reading as "no wheels".
cid="$(docker create --platform "${PLATFORM}" "${IMAGE}" true 2>&1)" || {
  echo "::error::check-virtualenv-seeds: could not create a container from ${IMAGE} for ${PLATFORM}: ${cid}" >&2
  exit 1
}
trap 'docker rm -f "${cid}" >/dev/null 2>&1 || true' EXIT
listing="$(docker export "${cid}" | python3 -I -c '
import re, sys, tarfile
SEED = re.compile(r"(^|/)virtualenv/seed/wheels/embed/[^/]+[.]whl$")
ENSURE = re.compile(r"^usr/share/python-wheels/[^/]+[.]whl$")
PYTHONS = {"usr/bin/python3", "bin/python3", "usr/local/bin/python3"}
seeds, ensure, python = [], [], False
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as tar:
    for member in tar:
        name = member.name
        while name.startswith("./"):
            name = name[2:]
        name = name.lstrip("/")
        if member.isdir():
            continue
        if SEED.search(name):
            seeds.append(name)
        elif ENSURE.match(name):
            ensure.append(name)
        if name in PYTHONS:
            python = True
for name in sorted(seeds):
    print("SEED /" + name)
for name in sorted(ensure):
    print("ENSUREPIP /" + name)
print("PYTHON3 " + ("yes" if python else "no"))
print("LISTED %d %d" % (len(seeds), len(ensure)))
')" || {
  echo "::error::check-virtualenv-seeds: could not read the filesystem of ${IMAGE} (${PLATFORM})" >&2
  exit 1
}
listed="$(sed -n 's/^LISTED \([0-9]*\) \([0-9]*\)$/\1 \2/p' <<<"${listing}")"
if [ -z "${listed}" ]; then
  echo "::error::check-virtualenv-seeds: the filesystem listing did not complete; refusing to report clean" >&2
  exit 1
fi
seed_count="${listed% *}"
ensurepip_count="${listed#* }"

if [ "${seed_count}" -eq 0 ] && [ "${ensurepip_count}" -eq 0 ]; then
  echo "  no virtualenv seed wheels and no ensurepip wheels in the image - nothing to check"
  exit 0
fi
if ! grep -q '^PYTHON3 yes$' <<<"${listing}"; then
  echo "::error::${IMAGE} carries seed or ensurepip wheels but no python3 to inspect them with; refusing to report clean" >&2
  exit 1
fi

if [ "${seed_count}" -gt 0 ]; then
wheels="$(sed -n 's|^SEED .*/||p' <<<"${listing}" | sort)"
echo "  seed wheels found:"
sed -n 's/^SEED /    /p' <<<"${listing}"

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
    printf '      present: %s\n' "${versions//$'\n'/$'\n'      present: }"
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
# the finding appear with no file path. For every virtualenv-*.dist-info in the
# image this asserts:
#
#   * RECORD and the SBOM name no seed wheel version other than the one on
#     disk: the original text rule (same pattern, same match), and structurally
#     - any SBOM component named like a seed project must carry the version on
#     disk, so a stale entry with no name-version token (only a purl such as
#     pkg:pypi/pip@26.0.1, which scanners do read) is caught as well;
#   * every RECORD hash and size matches its file;
#   * for each seed wheel, the SBOM's hash, file list, per-file hash and size,
#     and vendored versions match that wheel, and every wheel is declared;
#   * every seed wheel directory has a virtualenv dist-info beside it.
#
# The SBOM's metadata.tools and formulation sections are build provenance, not
# inventory. CycloneDX defines them as the tools used to produce the document
# and how the component was manufactured, and virtualenv records its own build
# environment there: 21.14.12 bundles setuptools 84.2.1 but was built with
# setuptools 84.0.0, and that tool entry failed this check while it read the
# whole file as text. Scanners do not report tool entries as installed
# packages. Seed-name references found there are printed as PROVENANCE so
# nothing is hidden, but they do not decide the result.
#
# The interpreter runs isolated (-I), so nothing on the image PYTHONPATH can
# shadow the modules this check uses. A failure to run, or a run that does not
# reach its DONE line, fails the image.
inventory="$(docker run --rm --platform "${PLATFORM}" --entrypoint python3 "${IMAGE}" -I -c '
import base64, csv, hashlib, io, json, os, re, zipfile

TOKEN = re.compile("(pip|setuptools)-[0-9][^\"/,\\s]*")
HASHES = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
OWN_RECORD = re.compile(r"^[^/]+\.dist-info/RECORD$")

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def prop(node, name):
    for p in node.get("properties") or []:
        if p.get("name") == name:
            return p.get("value")
    return None

def pins(text):
    out = {}
    for raw in text.splitlines():
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,]+)", raw.split("#", 1)[0].strip())
        if m:
            out[norm(m.group(1))] = m.group(2)
    return out

def manifest_version(manifest, data, name):
    text = data.decode("utf8", "ignore")
    if manifest.endswith("vendor.txt"):
        return pins(text).get(norm(name))
    if manifest.endswith(".dist-info/METADATA"):
        for line in text.splitlines():
            if not line.strip():
                break
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()
    return None

def bom_refs(node):
    if isinstance(node, dict):
        own = {node["bom-ref"]} if isinstance(node.get("bom-ref"), str) else set()
        return own.union(*[bom_refs(v) for v in node.values()])
    if isinstance(node, list):
        return set().union(*[bom_refs(v) for v in node])
    return set()

def digest_ok(entry, data):
    algorithm = HASHES.get(entry.get("alg"))
    return bool(algorithm) and entry.get("content") == algorithm(data).hexdigest()

def stale(message):
    print("STALE " + message)

# Same discovery as before (find / -type d -name virtualenv-*.dist-info),
# without walking the kernel pseudo-filesystems. Seed wheel directories are
# collected in the same walk: one with no virtualenv dist-info beside it has
# nothing declaring its wheels, so nothing here could vouch for them.
dist_infos, embeds = [], []
for top, dirs, files in os.walk("/"):
    if top == "/":
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
    dist_infos += [os.path.join(top, d) for d in dirs if d.startswith("virtualenv-") and d.endswith(".dist-info")]
    if top.endswith("/virtualenv/seed/wheels/embed") and any(f.endswith(".whl") for f in files):
        embeds.append(top)
for embed in sorted(embeds):
    site = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(embed))))
    if not any(d.startswith("virtualenv-") and d.endswith(".dist-info") for d in os.listdir(site)):
        stale("seed wheels in %s have no virtualenv dist-info beside them to declare them" % embed)

for dist_info in sorted(dist_infos):
    site = os.path.dirname(dist_info)
    embed = os.path.join(site, "virtualenv", "seed", "wheels", "embed")
    wheels = {}
    if os.path.isdir(embed):
        wheels = {n: os.path.join(embed, n) for n in sorted(os.listdir(embed)) if n.endswith(".whl")}
    kept = {n.split("-", 1)[0]: n.split("-", 2)[1] for n in wheels}
    kept_names = {norm(project): version for project, version in kept.items()}
    texts = []
    print("DISTINFO " + dist_info)

    record = os.path.join(dist_info, "RECORD")
    if os.path.isfile(record):
        text = open(record, encoding="utf-8").read()
        texts.append(text)
        listed = set()
        for row in csv.reader(io.StringIO(text)):
            if not row:
                continue
            path, digest, size = (row + ["", ""])[:3]
            if "/seed/wheels/embed/" in path and path.endswith(".whl"):
                listed.add(path.rsplit("/", 1)[-1])
            if not digest:
                continue
            target = os.path.normpath(os.path.join(site, path))
            if not os.path.isfile(target):
                stale("RECORD declares %s, which is not on disk" % path)
                continue
            data = open(target, "rb").read()
            expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            if digest != expected or size != str(len(data)):
                stale("RECORD hash or size for %s does not match the file" % path)
        for name in sorted(set(wheels) - listed):
            stale("seed wheel %s is on disk but missing from RECORD" % name)

    sbom_dir = os.path.join(dist_info, "sboms")
    for sbom_name in sorted(os.listdir(sbom_dir)) if os.path.isdir(sbom_dir) else []:
        if not sbom_name.endswith(".json"):
            continue
        document = json.load(open(os.path.join(sbom_dir, sbom_name), encoding="utf-8"))
        # Provenance: metadata.tools, formulation, and the dependency entries
        # and edges of the bom-refs defined under metadata.tools.
        metadata = dict(document.get("metadata") or {})
        tools = metadata.pop("tools", None)
        tool_refs = bom_refs(tools)
        dependencies, tool_graph = [], []
        for entry in document.get("dependencies") or []:
            if entry.get("ref") in tool_refs:
                tool_graph.append(entry)
                continue
            edges = entry.get("dependsOn") or []
            tool_graph += [ref for ref in edges if ref in tool_refs]
            dependencies.append(dict(entry, dependsOn=[ref for ref in edges if ref not in tool_refs]) if "dependsOn" in entry else entry)
        provenance = {"metadata.tools": tools, "formulation": document.get("formulation"), "dependencies of tools": tool_graph}
        for section, content in sorted(provenance.items()):
            for token in sorted({m.group(0) for m in TOKEN.finditer(json.dumps(content))} if content else []):
                print("PROVENANCE %s (%s %s: the build environment of the upstream wheel)" % (token, sbom_name, section))
        view = {k: v for k, v in document.items() if k != "formulation"}
        view["metadata"] = metadata
        if "dependencies" in document:
            view["dependencies"] = dependencies
        texts.append(json.dumps(view))

        declared = set()
        for component in document.get("components") or []:
            name, version = norm(str(component.get("name", ""))), component.get("version")
            wheel = next((n for n in wheels if norm(n.split("-", 1)[0]) == name and n.split("-", 2)[1] == version), None)
            if wheel is None:
                if prop(component, "virtualenv:bundled-wheel") is not None:
                    stale("%s declares seed wheel %s %s, which is not on disk" % (sbom_name, name, version))
                elif name in kept_names and version is not None:
                    # Structural, so a component with no name-version token
                    # (only a purl such as pkg:pypi/pip@26.0.1) is caught too.
                    stale("%s declares %s %s, but the seed wheel on disk is %s %s" % (sbom_name, name, version, name, kept_names[name]))
                continue
            declared.add(wheel)
            data = open(wheels[wheel], "rb").read()
            hashes = component.get("hashes") or []
            for entry in hashes:
                if not digest_ok(entry, data):
                    stale("%s: %s of %s does not match the wheel" % (sbom_name, entry.get("alg"), wheel))
            current = {HASHES[e["alg"]](data).hexdigest() for e in hashes if e.get("alg") in HASHES}
            for identity in (component.get("evidence") or {}).get("identity") or []:
                for method in identity.get("methods") or []:
                    if method.get("technique") == "hash-comparison" and method.get("value") not in current:
                        stale("%s: hash evidence for %s does not match the wheel" % (sbom_name, wheel))
            with zipfile.ZipFile(wheels[wheel]) as archive:
                members = {i.filename: archive.read(i) for i in archive.infolist() if not i.is_dir()}
            nested = component.get("components") or []
            files = {n.get("name"): n for n in nested if n.get("type") == "file"}
            if files:
                expected = {n: c for n, c in members.items() if not OWN_RECORD.match(n)}
                for member in sorted(set(files) - set(expected)):
                    stale("%s lists %s in %s, which has no such file" % (sbom_name, member, wheel))
                for member in sorted(set(expected) - set(files)):
                    stale("%s: %s contains %s, which is not listed" % (sbom_name, wheel, member))
                for member in sorted(set(files) & set(expected)):
                    node, content = files[member], expected[member]
                    if not all(digest_ok(e, content) for e in node.get("hashes") or []):
                        stale("%s: hash of %s:%s does not match" % (sbom_name, wheel, member))
                    if prop(node, "size") not in (None, str(len(content))):
                        stale("%s: size of %s:%s does not match" % (sbom_name, wheel, member))
            libraries = [n for n in nested if n.get("type") == "library"]
            for node in libraries:
                manifest = prop(node, "virtualenv:vendored-manifest")
                if manifest is None:
                    continue
                found = manifest_version(manifest, members[manifest], str(node.get("name", ""))) if manifest in members else None
                if found != node.get("version"):
                    stale("%s declares %s vendoring %s %s, but its %s gives %s" % (sbom_name, wheel, node.get("name"), node.get("version"), manifest, found))
            for manifest in sorted({prop(n, "virtualenv:vendored-manifest") or "" for n in libraries}):
                if manifest.endswith("vendor.txt") and manifest in members:
                    listed = {norm(str(n.get("name", ""))) for n in libraries if prop(n, "virtualenv:vendored-manifest") == manifest}
                    on_disk = pins(members[manifest].decode("utf8", "ignore"))
                    for pin in sorted(set(on_disk) - listed):
                        stale("%s: %s vendors %s %s, which is not declared" % (sbom_name, wheel, pin, on_disk[pin]))
        for name in sorted(set(wheels) - declared):
            stale("%s does not declare seed wheel %s" % (sbom_name, name))

    refs = sorted({m.group(0) for text in texts for m in TOKEN.finditer(text)})
    for ref in refs:
        print("REF " + ref)
    for project, version in sorted(kept.items()):
        for ref in refs:
            if ref.startswith(project + "-") and not re.match(re.escape(project + "-" + version) + "([^0-9]|$)", ref):
                stale("inventory still declares %s, which is not on disk (kept: %s %s)" % (ref, project, version))

print("DONE %d" % len(dist_infos))
' 2>&1)" || {
  echo "::error::check-virtualenv-seeds: declared inventory check failed to run" >&2
  printf '  %s\n' "${inventory//$'\n'/$'\n'  }" >&2
  exit 1
}

echo "  declared inventory (RECORD and SBOM):"
printf '    %s\n' "${inventory//$'\n'/$'\n'    }"

if ! grep -q '^DONE ' <<<"${inventory}"; then
  echo "::error::declared inventory check did not complete; refusing to report clean" >&2
  exit 1
fi

if grep -q '^STALE ' <<<"${inventory}"; then
  echo "::error::the declared inventory disagrees with the seed wheels on disk:" >&2
  grep '^STALE ' <<<"${inventory}" | sed 's/^STALE /      /' >&2
  exit 1
fi
fi

# Third surface: what is INSIDE each seed wheel and each ensurepip wheel.
#
# The checks above only compare seed wheels against each other, so a single
# wheel with no duplicate passes even when the code inside it is vulnerable.
# That is exactly what happened: virtualenv 21.14.5 bundles a pip 26.2.1 seed
# wheel vendoring urllib3 2.7.0, while the ensurepip wheel Chainguard ships at
# /usr/share/python-wheels carries the patched 2.8.0. Every environment made by
# "virtualenv" or by poetry - which creates its environments through virtualenv
# - gets the 2.7.0 copy. Measured, not assumed. No scanner here catches it:
# Trivy does not read inside .whl files.
#
# For every seed wheel, wherever its virtualenv is installed:
#
#   * BEHIND: it vendors nothing older than the distro wheel of the same
#     version, which the distribution patches - so a future patch is picked up
#     with no edit here. Only packages present in both are compared, and only
#     a seed version strictly older than the reference is a finding;
#   * INCONSISTENT: its own RECORD lists every member with the right hash and
#     size, and its bundled bom.cdx.json agrees with its vendor.txt and
#     references nothing it does not declare;
#   * VENDORS: it vendors nothing in REMOVED_VENDORED (what harden-pip-vendor.py
#     removes from the installed pip), and - when the installed copy of the
#     same project beside it is the SAME version - no top-level vendored entry
#     that copy does not carry. A package directory is not satisfied by a type
#     stub of the same name.
#
# Every ensurepip wheel under /usr/share/python-wheels - what "python -m venv"
# seeds environments from - is held to INCONSISTENT and VENDORS too.
#
# The walk must inspect every wheel the first surface listed; fewer means a
# wheel went unchecked, which fails rather than passes.
echo "  checking seed and ensurepip wheel interiors"
interior="$(docker run --rm --platform "${PLATFORM}" --entrypoint python3 "${IMAGE}" -I -c '
import base64, csv, hashlib, io, json, os, re, sys, zipfile

# {package directory under <project>/_vendor: distribution vendor.txt names it
# by}, read by the caller from REMOVED_VENDORED in harden-pip-vendor.py.
POLICY = json.loads(sys.argv[1])
ENSUREPIP_DIR = "/usr/share/python-wheels"
OWN_RECORD = re.compile(r"^[^/]+[.]dist-info/RECORD$")
PIN = re.compile(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,]+)")

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def pins(text):
    out = {}
    for raw in text.splitlines():
        m = PIN.match(raw.split("#", 1)[0].strip())
        if m:
            out[norm(m.group(1))] = m.group(2)
    return out

def wheel_pins(members, dist):
    """name -> version from every <dist>/.../_vendor/vendor.txt in a wheel (the original rule)."""
    out = {}
    for n, data in members.items():
        if n.endswith("_vendor/vendor.txt") and n.startswith(dist + "/"):
            out.update(pins(data.decode("utf8", "ignore")))
    return out

def parse(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])

def read_members(path):
    with zipfile.ZipFile(path) as zf:
        return {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}

def self_problems(members, dist):
    """A wheel checked against itself: its RECORD, and bom.cdx.json vs vendor.txt."""
    out = []
    record = next((n for n in members if OWN_RECORD.match(n)), None)
    if record is None:
        out.append("has no RECORD, so none of its contents can be verified")
    else:
        rows = [r for r in csv.reader(io.StringIO(members[record].decode("utf-8"))) if r]
        for path, digest, size in ((r + ["", ""])[:3] for r in rows):
            if not digest:
                continue
            data = members.get(path)
            if data is None:
                out.append("RECORD lists %s, which the wheel lacks" % path)
                continue
            want = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            if digest != want or size != str(len(data)):
                out.append("RECORD hash or size for %s does not match" % path)
        for path in sorted(set(members) - {r[0] for r in rows}):
            out.append("%s is not in the wheel RECORD" % path)
    vendor = members.get(dist + "/_vendor/vendor.txt")
    bom = members.get(dist + "/_vendor/bom.cdx.json")
    if vendor is not None and bom is not None:
        pinned = pins(vendor.decode("utf8", "ignore"))
        doc = json.loads(bom)
        declared = {norm(str(c.get("name", ""))): c.get("version") for c in doc.get("components") or []}
        for name, version in sorted(pinned.items()):
            if declared.get(name) != version:
                out.append("bom.cdx.json gives %s %s, vendor.txt pins %s" % (name, declared.get(name), version))
        known = {c.get("bom-ref") for c in doc.get("components") or []}
        known.add(((doc.get("metadata") or {}).get("component") or {}).get("bom-ref"))
        for entry in doc.get("dependencies") or []:
            for ref in [entry.get("ref")] + list(entry.get("dependsOn") or []):
                if ref not in known:
                    out.append("bom.cdx.json depends on %s, which it does not declare" % ref)
    return out

def policy_problems(members, dist):
    """What REMOVED_VENDORED says no wheel here may vendor."""
    out = []
    vendor = members.get(dist + "/_vendor/vendor.txt")
    pinned = pins(vendor.decode("utf8", "ignore")) if vendor is not None else {}
    for package, distribution in sorted(POLICY.items()):
        if any(n.startswith(dist + "/_vendor/" + package + "/") for n in members):
            out.append("vendors %s/, which REMOVED_VENDORED removes" % package)
        if norm(distribution) in pinned:
            out.append("vendor.txt still pins %s %s, which REMOVED_VENDORED removes" % (distribution, pinned[norm(distribution)]))
    return out

def vendored_entries(names, prefix):
    """Top-level entries under prefix: a directory as name/, a file as its name."""
    out = set()
    for n in names:
        if n.startswith(prefix) and len(n) > len(prefix):
            rest = n[len(prefix):]
            out.add(rest.split("/", 1)[0] + "/" if "/" in rest else rest)
    return out - {"__pycache__/"}

# Every seed wheel anywhere in the image, found the way the inventory surface
# finds virtualenv: a walk of / without the kernel pseudo-filesystems. Fixed
# site-packages roots would miss a virtualenv installed elsewhere (/opt/venv,
# a tool venv), and a missed wheel must never read as a pass.
seeds = []
for top, dirs, files in os.walk("/"):
    if top == "/":
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev")]
    if top.endswith("/virtualenv/seed/wheels/embed"):
        seeds += [os.path.join(top, f) for f in sorted(files) if f.endswith(".whl")]
ensurepip = []
if os.path.isdir(ENSUREPIP_DIR):
    ensurepip = [os.path.join(ENSUREPIP_DIR, f) for f in sorted(os.listdir(ENSUREPIP_DIR)) if f.endswith(".whl")]

problems = compared = inspected_seeds = inspected_ensurepip = 0
for seed in sorted(seeds):
    base = os.path.basename(seed)
    dist, version = base.split("-", 2)[:2]
    site = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(seed)))))
    try:
        members = read_members(seed)
    except Exception as e:
        print("UNREADABLE %s: %s" % (seed, e))
        problems += 1
        continue
    inspected_seeds += 1
    for problem in self_problems(members, dist):
        print("INCONSISTENT %s: %s" % (seed, problem))
        problems += 1
    for problem in policy_problems(members, dist):
        print("VENDORS %s %s" % (seed, problem))
        problems += 1
    # The installed copy of the same project beside THIS virtualenv is the
    # reference, and only at the same version: a different pip release may
    # vendor a different set for reasons that are not hardening.
    seed_entries = vendored_entries(members, dist + "/_vendor/")
    if seed_entries:
        vendor_dir = os.path.join(site, dist, "_vendor")
        installed = sorted(d[len(dist) + 1:-len(".dist-info")] for d in os.listdir(site) if d.startswith(dist + "-") and d.endswith(".dist-info"))
        if not os.path.isdir(vendor_dir):
            print("NOINSTALLED %s: no installed %s beside it; checked against REMOVED_VENDORED only" % (seed, dist))
        elif installed != [version]:
            print("NOTE %s: the installed %s beside it is %s, not %s; checked against REMOVED_VENDORED only" % (seed, dist, ",".join(installed) or "of unknown version", version))
        else:
            here = {e + "/" if os.path.isdir(os.path.join(vendor_dir, e)) else e for e in os.listdir(vendor_dir)}
            for entry in sorted(seed_entries - here):
                print("VENDORS %s vendors %s, which the installed %s %s at %s does not carry" % (seed, entry, dist, version, vendor_dir))
                problems += 1
            print("VENDORCHECK %s: %d vendored entries compared with the installed %s %s" % (seed, len(seed_entries), dist, version))
    # The distro wheel of the same version, which the distribution patches.
    reference = os.path.join(ENSUREPIP_DIR, base)
    if not os.path.isfile(reference):
        print("NOREF %s has no distro wheel of the same version to compare against" % base)
        continue
    try:
        ref_members = read_members(reference)
    except Exception as e:
        print("UNREADABLE %s: %s" % (reference, e))
        problems += 1
        continue
    sp, rp = wheel_pins(members, dist), wheel_pins(ref_members, dist)
    for name, sv in sorted(sp.items()):
        rv = rp.get(name)
        if rv is None:
            continue
        compared += 1
        if parse(sv) < parse(rv):
            print("BEHIND %s vendors %s %s but the distro wheel has %s" % (base, name, sv, rv))
            problems += 1

# The wheels "python -m venv" seeds every environment from. Same standard.
for wheel in ensurepip:
    dist = os.path.basename(wheel).split("-", 1)[0]
    try:
        members = read_members(wheel)
    except Exception as e:
        print("UNREADABLE %s: %s" % (wheel, e))
        problems += 1
        continue
    inspected_ensurepip += 1
    for problem in self_problems(members, dist):
        print("INCONSISTENT %s: %s" % (wheel, problem))
        problems += 1
    for problem in policy_problems(members, dist):
        print("VENDORS %s %s" % (wheel, problem))
        problems += 1

print("INSPECTED %d %d" % (inspected_seeds, inspected_ensurepip))
print("COMPARED %d" % compared)
print("DONE %d" % problems)
' "${policy}" 2>&1)" || {
  echo "::error::check-virtualenv-seeds: wheel interior check failed to run" >&2
  printf '  %s\n' "${interior//$'\n'/$'\n'  }" >&2
  exit 1
}

printf '  %s\n' "${interior//$'\n'/$'\n'  }"

if ! grep -q '^DONE ' <<<"${interior}"; then
  echo "::error::wheel interior check did not complete; refusing to report clean" >&2
  exit 1
fi
if grep -q '^UNREADABLE ' <<<"${interior}"; then
  echo "::error::a seed or ensurepip wheel could not be read; refusing to report clean" >&2
  exit 1
fi
if grep -q '^BEHIND ' <<<"${interior}"; then
  echo "::error::a virtualenv seed wheel vendors a dependency older than the distro wheel of the same version. Every environment created from it inherits that code, and no scanner reads inside a .whl." >&2
  exit 1
fi
if grep -q '^INCONSISTENT ' <<<"${interior}"; then
  echo "::error::a wheel disagrees with its own RECORD or bom.cdx.json:" >&2
  grep '^INCONSISTENT ' <<<"${interior}" | sed 's/^INCONSISTENT /      /' >&2
  exit 1
fi
if grep -q '^VENDORS ' <<<"${interior}"; then
  echo "::error::a seed or ensurepip wheel vendors code the installed pip was hardened to drop; every environment created from it gets that code back:" >&2
  grep '^VENDORS ' <<<"${interior}" | sed 's/^VENDORS /      /' >&2
  exit 1
fi
inspected="$(sed -n 's/^INSPECTED \([0-9]*\) \([0-9]*\)$/\1 \2/p' <<<"${interior}")"
if [ "${inspected}" != "${seed_count} ${ensurepip_count}" ]; then
  echo "::error::the interior check inspected ${inspected:-no} wheels (seed ensurepip) but the image holds ${seed_count} ${ensurepip_count}; a wheel went unchecked" >&2
  exit 1
fi

echo "check-virtualenv-seeds: ok - ${seed_count} seed and ${ensurepip_count} ensurepip wheel(s) inspected: one seed wheel per project, RECORD and SBOM match the wheels on disk, every wheel consistent with itself, none behind the distro wheel or vendoring what the installed pip dropped"
