#!/usr/bin/env python3
"""Remove virtualenv's superseded seed wheels and correct its inventory.

virtualenv ships several pip and setuptools wheels under
``virtualenv/seed/wheels/embed`` so it can seed a new environment without a
network fetch. It keeps one set per supported Python version, so the copies
used for older interpreters stay behind at their original versions and keep
their original vulnerabilities.

Verified in this repository on 2026-09-29: the published
python-3.14-base-linux-arm64 and python-3.13-base images each carry
pip 26.0.1 (CVE-2026-13346, CVE-2026-3219, CVE-2026-6357, CVE-2026-8643)
and setuptools 82.0.1 (CVE-2026-59890) alongside the current pip 26.2.1 and
setuptools 84.0.0. The superseded pair is referenced only by an older
interpreter entry. These images ship a single Python version, so those wheels
can never be selected here.

Three things make this worth a script rather than an ignore rule:

  * There is no installable fix. virtualenv 21.14.0, the current release, still
    bundles exactly those wheels, and virtualenv cannot simply be dropped
    because poetry imports it to create environments.

  * Deleting the wheel files alone does not resolve the finding. virtualenv
    publishes its own CycloneDX SBOM at
    ``virtualenv-<version>.dist-info/sboms/virtualenv.cdx.json`` and lists the
    wheels in ``RECORD``. Scanners read that declared inventory, which is why
    the finding reports no file path. The inventory has to agree with what is
    actually on disk.

  * A suppression would not reach anyone downstream. Consumers scan the
    published image with their own tooling and never see this repository's
    ignore file, so suppressing here would leave them looking at findings we
    had quietly accepted.

The order below is deliberate and is what keeps the result honest: the
vulnerable wheels are deleted first, and only then is the inventory rewritten
to describe what remains. Editing the SBOM without removing the files would
misreport the contents of the image.

Nothing is pinned to a version. The highest version present of each project is
kept and every older copy is removed, so a future virtualenv that bundles a new
stale wheel is handled without editing this file.

"Consistent" covers every integrity field the inventory carries, not only the
versions: the RECORD line of each file this script writes (sha256 and size),
and in the SBOM the hash of each seed wheel, the hash and size of every file
inside it, and the version of every package it vendors. All of them are
derived from the bytes left on disk after the last write, so the declared
inventory can be re-verified by anyone against the image.

The SBOM's ``metadata.tools`` and ``formulation`` sections are deliberately
left untouched. In CycloneDX the first lists the tools used to produce the
document and the second describes how the component was manufactured.
virtualenv records its own build environment in them: the tools (hatchling,
setuptools-scm and the setuptools release they ran on), and a "wheel-build"
workflow whose resources are those tools and whose output is virtualenv
itself. That is provenance of how the upstream wheel was built, not a
description of what this image contains, and scanners do not read it as
installed packages. virtualenv 21.14.12, for example, bundles setuptools
84.2.1 but was built with setuptools 84.0.0. Rewriting either section would
falsify a build record, for the same reason the attribution files are
excluded in verify().
"""

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import zipfile
from collections import defaultdict

LIB_ROOT = pathlib.Path("/home/nonroot/.local/lib")

# The embed directory is located by glob rather than a fixed path because the
# python3 compatibility symlink is created later in the Dockerfile and does not
# exist yet when this runs.
EMBED_GLOB = "python3*/site-packages/virtualenv/seed/wheels/embed"

# Wheels the distribution ships and patches. ensurepip installs from here, which
# is why "python -m venv" produces a clean environment while "virtualenv" does
# not: virtualenv seeds from its own bundled copy of the same pip version.
DISTRO_WHEEL_DIR = pathlib.Path("/usr/share/python-wheels")

# CycloneDX hash algorithm names this script can recompute. An algorithm outside
# this set stops the build rather than leaving a hash that no longer describes
# the file it is attached to.
SBOM_HASH_ALGORITHMS = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
}

# virtualenv's SBOM declares every member of a bundled wheel except the wheel's
# own RECORD, which lists the other members and cannot list itself with a hash.
WHEEL_OWN_RECORD = re.compile(r"^[^/]+\.dist-info/RECORD$")

# A file this script wrote or deleted. Every one of them gets its RECORD line
# refreshed or dropped once all writes are done, so no hash is computed over
# bytes that are about to change again.
Touched = set[pathlib.Path]

# Vendored packages harden-pip-vendor.py removes from the installed pip, as
# {package directory under <dist>/_vendor: the distribution vendor.txt names it
# by}. The same packages are removed from the seed wheels here: otherwise every
# environment created by virtualenv, or by poetry through virtualenv, gets back
# the code the installed pip was hardened to drop. Must stay identical to
# REMOVED_VENDORED in harden-pip-vendor.py; a unit test enforces it.
REMOVED_VENDORED = {"pkg_resources": "setuptools"}


def version_key(version: str) -> tuple:
    """Numeric-aware sort key, so 26.10 sorts above 26.2."""
    return tuple(
        int(part) if part.isdigit() else part for part in re.split(r"[.\-]", version)
    )


def find_embed() -> pathlib.Path:
    matches = sorted(LIB_ROOT.glob(EMBED_GLOB))
    if not matches:
        sys.exit(f"harden-virtualenv-seeds: no seed wheels found under {LIB_ROOT}")
    return matches[-1]


def remove_superseded(embed: pathlib.Path, touched: Touched) -> dict[str, str]:
    """Delete all but the highest version of each bundled project.

    Returns a mapping of removed wheel filename to the filename kept in its
    place, which the inventory rewrites below use.
    """
    grouped: dict[str, list] = defaultdict(list)
    for wheel in embed.glob("*.whl"):
        name, version = wheel.name.split("-", 2)[:2]
        grouped[name].append((version_key(version), version, wheel))

    replacements: dict[str, str] = {}
    for name, entries in sorted(grouped.items()):
        entries.sort()
        kept = entries[-1]
        print(f"  keeping {name} {kept[1]}")
        for _, version, wheel in entries[:-1]:
            print(f"  removing superseded {name} {version}")
            replacements[wheel.name] = kept[2].name
            wheel.unlink()
            touched.add(wheel)
    return replacements


def rewrite_bundle_support(
    embed: pathlib.Path, replacements: dict[str, str], touched: Touched
) -> None:
    """Point BUNDLE_SUPPORT at the wheels that are still present."""
    init = embed / "__init__.py"
    original = init.read_text(encoding="utf-8")
    updated = original
    for removed, kept in replacements.items():
        updated = updated.replace(removed, kept)
    if updated != original:
        init.write_text(updated, encoding="utf-8")
        touched.add(init)
        print("  BUNDLE_SUPPORT re-pointed")
    for cached in embed.glob("__pycache__/*.pyc"):
        cached.unlink()


def rewrite_inventory(
    site_packages: pathlib.Path, replacements: dict[str, str], touched: Touched
) -> None:
    """Drop the removed wheels from the shipped CycloneDX SBOM.

    This is what scanners read as the inventory, which is why the finding
    reports no file path. The components are REMOVED rather than relabelled:
    the image no longer contains those versions at all, so deleting the entry
    is the accurate description. Rewriting a version in place would instead
    leave a duplicate component and dangling bom-ref, purl and dependency
    references pointing at a package that is not there.

    Only ``components``, ``dependencies`` and ``compositions`` are edited;
    ``metadata.tools`` and ``formulation`` are build provenance and stay as
    published (see the module docstring). RECORD is handled by
    refresh_record(), after the last write, because the SBOM's own RECORD line
    has to describe its final bytes.
    """
    removed_pairs = {
        (removed.split("-", 2)[0], removed.split("-", 2)[1]) for removed in replacements
    }
    stale_refs = {f"pkg:pypi/{name}@{version}" for name, version in removed_pairs}

    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        for sbom_path in dist_info.glob("sboms/*.json"):
            document = json.loads(sbom_path.read_text(encoding="utf-8"))

            kept_components = [
                component
                for component in document.get("components", [])
                if (component.get("name"), component.get("version"))
                not in removed_pairs
            ]
            dropped = len(document.get("components", [])) - len(kept_components)
            if not dropped:
                continue
            document["components"] = kept_components

            # Drop dependency nodes for the removed refs, and any edge to them.
            dependencies = []
            for entry in document.get("dependencies", []):
                if entry.get("ref") in stale_refs:
                    continue
                if "dependsOn" in entry:
                    entry["dependsOn"] = [
                        ref for ref in entry["dependsOn"] if ref not in stale_refs
                    ]
                dependencies.append(entry)
            if "dependencies" in document:
                document["dependencies"] = dependencies

            for composition in document.get("compositions", []):
                if "assemblies" in composition:
                    composition["assemblies"] = [
                        ref
                        for ref in composition["assemblies"]
                        if ref not in stale_refs
                    ]

            sbom_path.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )
            touched.add(sbom_path)
            print(f"  {sbom_path.name}: {dropped} component(s) removed")


def _vendored_pins(wheel: pathlib.Path, dist: str) -> dict[str, str]:
    """name -> version from <dist>/_vendor/vendor.txt inside a wheel."""
    pins: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith(f"{dist}/") and name.endswith("_vendor/vendor.txt"):
                pins.update(_parse_pins(archive.read(name).decode("utf8", "ignore")))
    return pins


def _version_tuple(value: str) -> tuple:
    return tuple(int(part) for part in re.findall(r"\d+", value)[:4])


def replace_with_distro_wheels(
    embed: pathlib.Path, touched: Touched
) -> dict[str, dict[str, tuple[str, str]]]:
    """Swap each bundled seed wheel for the distribution's patched wheel.

    virtualenv bundles upstream pip verbatim. Upstream pip 26.2.1 vendors
    urllib3 2.7.0 and msgpack 1.1.2; the distribution patches its own copy of
    the same pip version to 2.8.0 and 1.2.1. Because virtualenv seeds from its
    bundle, every environment created by virtualenv - and by poetry, which
    creates environments through virtualenv - inherits the unpatched code,
    while "python -m venv" does not. No scanner reports it, because none of
    them read inside a .whl.

    Only a wheel of exactly the same file name is used, so this never changes
    which pip version virtualenv seeds; it changes only whose build of it. A
    distro wheel that is not ahead on anything is left alone, so this is a
    no-op once the distribution and upstream agree.

    A swap must never lower anything. If the distro wheel is ahead on one
    vendored package but behind on another, or no longer vendors one the
    bundled wheel has, swapping would trade one fix for a regression that no
    later check can see: the interior gate compares the seed wheel with the
    distro wheel, and after a swap those are the same file. Neither choice is
    safe then, so the build stops and names both sides.

    Returns {wheel_name: {dep: (old, new)}} for the wheels actually replaced.
    """
    if not DISTRO_WHEEL_DIR.is_dir():
        print(f"  no {DISTRO_WHEEL_DIR}; leaving bundled wheels as shipped")
        return {}

    replaced: dict[str, dict[str, tuple[str, str]]] = {}
    for wheel in sorted(embed.glob("*.whl")):
        distro = DISTRO_WHEEL_DIR / wheel.name
        if not distro.is_file():
            continue
        dist = wheel.name.split("-", 1)[0]
        try:
            bundled_pins = _vendored_pins(wheel, dist)
            distro_pins = _vendored_pins(distro, dist)
        except (OSError, zipfile.BadZipFile) as error:
            sys.exit(f"harden-virtualenv-seeds: cannot read {wheel.name}: {error}")

        behind = {}
        lowered = {}
        # A REMOVED_VENDORED package is stripped from whichever wheel is kept,
        # so a distro wheel that no longer carries it - or carries another
        # version of it - loses nothing by the swap.
        removed = {_normalize(name) for name in REMOVED_VENDORED.values()}
        for name, bundled_version in bundled_pins.items():
            if name in removed:
                continue
            distro_version = distro_pins.get(name)
            if distro_version is None:
                lowered[name] = (bundled_version, "absent")
                continue
            if distro_version == bundled_version:
                continue
            bundled_key = _version_tuple(bundled_version)
            distro_key = _version_tuple(distro_version)
            if bundled_key < distro_key:
                behind[name] = (bundled_version, distro_version)
            elif distro_key < bundled_key:
                lowered[name] = (bundled_version, distro_version)

        if not behind:
            continue
        if lowered:
            sys.exit(
                f"harden-virtualenv-seeds: refusing to swap {wheel.name} for the "
                "distro wheel: it is ahead on "
                + ", ".join(f"{d} {o} -> {n}" for d, (o, n) in sorted(behind.items()))
                + " but would lower "
                + ", ".join(f"{d} {o} -> {n}" for d, (o, n) in sorted(lowered.items()))
                + ". Keeping either wheel ships a vulnerable or regressed vendored "
                "package; this needs a decision, not a silent choice."
            )

        shutil.copyfile(distro, wheel)
        touched.add(wheel)
        replaced[wheel.name] = behind
        for dep, (was, now) in sorted(behind.items()):
            print(f"  {wheel.name}: {dep} {was} -> {now} (from the distro wheel)")

    return replaced


def _strip_requirement_lines(text: str, dists: set[str]) -> tuple[str, set[str]]:
    """vendor.txt without the lines pinning ``dists``; also returns those seen."""
    kept, seen = [], set()
    for line in text.splitlines(keepends=True):
        name = _normalize(line.split("#", 1)[0].strip().split("==")[0].strip())
        if name and name in dists:
            seen.add(name)
            continue
        kept.append(line)
    return "".join(kept), seen


def _strip_bom_components(text: str, dists: set[str]) -> str:
    """A pip bom.cdx.json without ``dists``, their dependency nodes and edges."""
    bom = json.loads(text)
    refs = {
        component.get("bom-ref")
        for component in bom.get("components", [])
        if _normalize(str(component.get("name", ""))) in dists
    }
    bom["components"] = [
        component
        for component in bom.get("components", [])
        if _normalize(str(component.get("name", ""))) not in dists
    ]
    if isinstance(bom.get("dependencies"), list):
        dependencies = []
        for entry in bom["dependencies"]:
            if entry.get("ref") in refs:
                continue
            if "dependsOn" in entry:
                entry["dependsOn"] = [r for r in entry["dependsOn"] if r not in refs]
            dependencies.append(entry)
        bom["dependencies"] = dependencies
    return json.dumps(bom, indent=2) + "\n"


def strip_removed_vendored(embed: pathlib.Path, touched: Touched) -> list[str]:
    """Remove REMOVED_VENDORED from each seed wheel that still vendors it.

    The same removal harden-pip-vendor.py makes in the installed pip: the
    package directory goes, and so do its vendor.txt pin and its bom.cdx.json
    component with that component's dependency node and edges. The wheel's
    own RECORD is rewritten to match its new contents, and every other member
    is copied with its original metadata, so the wheel differs only by what
    was removed. A type stub such as ``pkg_resources.pyi`` is kept, exactly
    as the installed hardening keeps it: it is not code.

    Strict like harden-pip-vendor.py: a removed package present without the
    vendor.txt pin that names it is an unexpected layout and stops the build.

    Returns the names of the wheels rewritten.
    """
    dists = {_normalize(name) for name in REMOVED_VENDORED.values()}
    rewritten = []
    for wheel in sorted(embed.glob("*.whl")):
        dist = wheel.name.split("-", 1)[0]
        prefixes = tuple(f"{dist}/_vendor/{package}/" for package in REMOVED_VENDORED)
        with zipfile.ZipFile(wheel) as archive:
            infos = archive.infolist()
            data = {info.filename: archive.read(info) for info in infos}
        doomed = {name for name in data if name.startswith(prefixes)}
        if not doomed:
            continue

        record_name = next((n for n in data if WHEEL_OWN_RECORD.match(n)), None)
        vendor_txt = f"{dist}/_vendor/vendor.txt"
        if record_name is None or vendor_txt not in data:
            sys.exit(
                f"harden-virtualenv-seeds: {wheel.name} vendors "
                f"{sorted(REMOVED_VENDORED)} but has no RECORD or {vendor_txt}; "
                "refusing to rewrite an unexpected layout"
            )

        changed: dict[str, bytes] = {}
        text, seen = _strip_requirement_lines(data[vendor_txt].decode("utf-8"), dists)
        present = {
            REMOVED_VENDORED[package]
            for package in REMOVED_VENDORED
            if any(n.startswith(f"{dist}/_vendor/{package}/") for n in doomed)
        }
        missing = {_normalize(name) for name in present} - seen
        if missing:
            sys.exit(
                f"harden-virtualenv-seeds: {wheel.name} vendors a package for "
                f"{sorted(missing)} that {vendor_txt} does not pin; refusing to "
                "guess"
            )
        changed[vendor_txt] = text.encode("utf-8")
        bom_name = f"{dist}/_vendor/bom.cdx.json"
        if bom_name in data:
            changed[bom_name] = _strip_bom_components(
                data[bom_name].decode("utf-8"), dists
            ).encode("utf-8")

        original_record = data[record_name].decode("utf-8")
        terminator = "\r\n" if "\r\n" in original_record else "\n"
        out = io.StringIO()
        writer = csv.writer(out, lineterminator=terminator)
        for row in csv.reader(io.StringIO(original_record)):
            if not row or row[0] in doomed:
                continue
            if row[0] in changed:
                content = changed[row[0]]
                row = [row[0], _record_digest(content), str(len(content))]
            writer.writerow(row)
        changed[record_name] = out.getvalue().encode("utf-8")

        temporary = wheel.with_name(wheel.name + ".tmp")
        with zipfile.ZipFile(temporary, "w") as archive:
            for info in infos:
                if info.filename in doomed:
                    continue
                archive.writestr(info, changed.get(info.filename, data[info.filename]))
        temporary.chmod(wheel.stat().st_mode & 0o7777)
        temporary.replace(wheel)
        touched.add(wheel)
        rewritten.append(wheel.name)
        files = len([n for n in doomed if not n.endswith("/")])
        print(
            f"  {wheel.name}: removed vendored {', '.join(sorted(REMOVED_VENDORED))} "
            f"({files} files) and its vendor.txt, bom.cdx.json and RECORD entries"
        )
    return rewritten


def rewrite_bundle_sha256(
    embed: pathlib.Path, replaced: dict, touched: Touched
) -> None:
    """Update virtualenv's own integrity record for the wheels we replaced.

    virtualenv SHA-256 verifies every bundled wheel on load via BUNDLE_SHA256
    and raises RuntimeError on mismatch, so replacing the bytes without
    updating this breaks "virtualenv create" outright. This is the step a naive
    copy misses.
    """
    if not replaced:
        return

    init = embed / "__init__.py"
    text = init.read_text(encoding="utf-8")
    if "BUNDLE_SHA256" not in text:
        sys.exit(
            "harden-virtualenv-seeds: BUNDLE_SHA256 not found in "
            f"{init}. virtualenv's integrity mechanism has changed; this "
            "script must be updated rather than silently skipping it."
        )

    for wheel_name in replaced:
        digest = hashlib.sha256((embed / wheel_name).read_bytes()).hexdigest()
        pattern = re.compile(
            r'("' + re.escape(wheel_name) + r'"\s*:\s*")[0-9a-f]{64}(")'
        )
        text, count = pattern.subn(r"\g<1>" + digest + r"\g<2>", text)
        if count == 0:
            sys.exit(
                f"harden-virtualenv-seeds: no BUNDLE_SHA256 entry for "
                f"{wheel_name}; refusing to leave a wheel virtualenv will reject"
            )
        print(f"  BUNDLE_SHA256 updated for {wheel_name} ({count} entr(y/ies))")

    init.write_text(text, encoding="utf-8")
    touched.add(init)
    # Stale bytecode would re-assert the old hash and the check would still fail.
    for cached in embed.glob("__pycache__/*.pyc"):
        cached.unlink()


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_pins(text: str) -> dict[str, str]:
    """name -> version from the text of a vendor.txt."""
    pins: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,]+)", line)
        if match:
            pins[_normalize(match.group(1))] = match.group(2)
    return pins


def _manifest_version(manifest: str, data: bytes, name: str) -> str | None:
    """The version a vendored package's manifest gives for it, if any.

    virtualenv's SBOM names the manifest each vendored package was read from:
    pip's ``_vendor/vendor.txt``, or the package's own ``.dist-info/METADATA``
    inside setuptools.
    """
    text = data.decode("utf8", "ignore")
    if manifest.endswith("vendor.txt"):
        return _parse_pins(text).get(_normalize(name))
    if manifest.endswith(".dist-info/METADATA"):
        for line in text.splitlines():
            if not line.strip():
                break  # the headers end at the first blank line
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()
    return None


def _property(node: dict, name: str) -> str | None:
    for prop in node.get("properties") or []:
        if prop.get("name") == name:
            return prop.get("value")
    return None


def _wheel_members(wheel: pathlib.Path) -> list[tuple[str, bytes]]:
    """(name, bytes) for every file in a wheel, in archive order."""
    with zipfile.ZipFile(wheel) as archive:
        return [
            (info.filename, archive.read(info))
            for info in archive.infolist()
            if not info.is_dir()
        ]


def _hash_entries(data: bytes, existing: list) -> list:
    """Recompute each declared hash for ``data``, keeping the algorithms."""
    refreshed = []
    for entry in existing:
        algorithm = SBOM_HASH_ALGORITHMS.get(entry.get("alg"))
        if algorithm is None:
            sys.exit(
                f"harden-virtualenv-seeds: SBOM hash algorithm {entry.get('alg')!r} "
                "cannot be recomputed here; refusing to leave a hash that no "
                "longer describes its file"
            )
        refreshed.append({**entry, "content": algorithm(data).hexdigest()})
    return refreshed


def _replace_values(node, mapping: dict[str, str]):
    """Copy of ``node`` with every string leaf found in ``mapping`` replaced."""
    if isinstance(node, dict):
        return {key: _replace_values(value, mapping) for key, value in node.items()}
    if isinstance(node, list):
        return [_replace_values(value, mapping) for value in node]
    if isinstance(node, str):
        return mapping.get(node, node)
    return node


def _refresh_component(document: dict, component: dict, wheel: pathlib.Path) -> None:
    """Re-derive one seed wheel's SBOM component from the wheel on disk."""
    data = wheel.read_bytes()

    # The wheel's own hash, and the evidence entry that repeats it.
    old_hashes = component.get("hashes") or []
    new_hashes = _hash_entries(data, old_hashes)
    component["hashes"] = new_hashes
    digest_map = {
        old["content"]: new["content"]
        for old, new in zip(old_hashes, new_hashes)
        if old.get("content")
    }
    if "evidence" in component:
        component["evidence"] = _replace_values(component["evidence"], digest_map)

    members = _wheel_members(wheel)
    by_name = dict(members)
    parent_ref = component.get("bom-ref", "")
    nested = component.get("components") or []

    # Every file inside the wheel, with its hash and size. Rebuilt from the
    # archive only when the SBOM declares files at all, so no detail is
    # invented that upstream did not publish.
    declared_files = {
        node.get("name"): node for node in nested if node.get("type") == "file"
    }
    files = []
    if declared_files:
        for name, content in members:
            if WHEEL_OWN_RECORD.match(name):
                continue
            node = declared_files.get(name) or {
                "type": "file",
                "bom-ref": f"{parent_ref}#{name}",
                "name": name,
                "hashes": [{"alg": "SHA-256"}],
                "properties": [],
            }
            node["hashes"] = _hash_entries(
                content, node.get("hashes") or [{"alg": "SHA-256"}]
            )
            properties = [
                prop
                for prop in node.get("properties") or []
                if prop.get("name") != "size"
            ]
            properties.append({"name": "size", "value": str(len(content))})
            node["properties"] = properties
            files.append(node)

    # Every vendored package, at the version its manifest in THIS wheel gives.
    # A package strip_removed_vendored() took out goes, with its edges; any
    # other package the manifest no longer gives stops the build.
    removed_dists = {_normalize(name) for name in REMOVED_VENDORED.values()}
    renamed: dict[str, str] = {}
    dropped: set[str] = set()
    libraries = []
    for node in nested:
        if node.get("type") != "library":
            continue
        manifest = _property(node, "virtualenv:vendored-manifest")
        if manifest is None:
            libraries.append(node)
            continue
        content = by_name.get(manifest)
        version = (
            None
            if content is None
            else _manifest_version(manifest, content, str(node.get("name", "")))
        )
        if version is None and _normalize(str(node.get("name", ""))) in removed_dists:
            dropped.add(str(node.get("bom-ref")))
            print(f"  SBOM: {wheel.name} no longer vendors {node.get('name')}")
            continue
        libraries.append(node)
        if version is None:
            sys.exit(
                f"harden-virtualenv-seeds: {wheel.name}: the SBOM declares "
                f"vendored {node.get('name')} from {manifest}, which this wheel "
                "does not provide; refusing to declare a package that is not there"
            )
        old = node.get("version")
        if version == old:
            continue
        for key in ("purl", "bom-ref"):
            value = node.get(key)
            if isinstance(value, str) and old and value.endswith(f"@{old}"):
                updated = value[: -len(old)] + version
                if key == "bom-ref":
                    renamed[value] = updated
                node[key] = updated
        node["version"] = version
        print(f"  SBOM: {wheel.name} vendors {node.get('name')} {old} -> {version}")

    others = [node for node in nested if node.get("type") not in ("file", "library")]
    if nested:
        component["components"] = (files if declared_files else []) + libraries + others

    if renamed or dropped:
        dependencies = []
        for entry in document.get("dependencies", []):
            if entry.get("ref") in dropped:
                continue
            if entry.get("ref") in renamed:
                entry["ref"] = renamed[entry["ref"]]
            if "dependsOn" in entry:
                entry["dependsOn"] = [
                    renamed.get(ref, ref)
                    for ref in entry["dependsOn"]
                    if ref not in dropped
                ]
            dependencies.append(entry)
        if "dependencies" in document:
            document["dependencies"] = dependencies
        for composition in document.get("compositions", []):
            for key in ("assemblies", "dependencies"):
                if key in composition:
                    composition[key] = [
                        renamed.get(ref, ref)
                        for ref in composition[key]
                        if ref not in dropped
                    ]


def refresh_sbom_for_replaced(
    site_packages: pathlib.Path, embed: pathlib.Path, replaced: dict, touched: Touched
) -> None:
    """Make the SBOM describe the wheels we just swapped in.

    The swapped wheel is the distribution's build of the same version, so its
    hash, the hash and size of most files inside it and some vendored versions
    all differ from upstream's. Each is re-derived from the wheel now on disk.
    Only that wheel's component is edited: a text substitution across the whole
    document would also rewrite a matching purl under ``metadata.tools`` or
    ``formulation``.
    """
    if not replaced:
        return

    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        for sbom_path in dist_info.glob("sboms/*.json"):
            document = json.loads(sbom_path.read_text(encoding="utf-8"))
            changed = False
            for wheel_name in replaced:
                name, version = wheel_name.split("-", 2)[:2]
                for component in document.get("components", []):
                    if (
                        _normalize(str(component.get("name", ""))) == _normalize(name)
                        and component.get("version") == version
                    ):
                        _refresh_component(document, component, embed / wheel_name)
                        changed = True
                        print(
                            f"  {sbom_path.name}: {wheel_name} re-derived from "
                            "the wheel on disk"
                        )
            if changed:
                sbom_path.write_text(
                    json.dumps(document, indent=2) + "\n", encoding="utf-8"
                )
                touched.add(sbom_path)


def _record_digest(data: bytes) -> str:
    return (
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    )


def refresh_record(site_packages: pathlib.Path, touched: Touched) -> None:
    """Bring RECORD in line with every file this script wrote or deleted.

    Runs once, after the last write, so each hash describes final bytes - the
    SBOM included, which earlier versions of this script rewrote without
    updating its own line. A file that is gone loses its line; a rewritten file
    gets a fresh sha256 and size. Lines for files this script did not touch are
    kept exactly as pip wrote them.
    """
    if not touched:
        return
    targets = {path.resolve() for path in touched}

    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        record = dist_info / "RECORD"
        if not record.exists():
            continue
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        refreshed = dropped = 0
        for row in csv.reader(io.StringIO(record.read_text(encoding="utf-8"))):
            if not row:
                continue
            target = (site_packages / row[0]).resolve()
            if target in targets:
                if not target.is_file():
                    dropped += 1
                    continue
                data = target.read_bytes()
                row = [row[0], _record_digest(data), str(len(data))]
                refreshed += 1
            writer.writerow(row)
        if refreshed or dropped:
            record.write_text(out.getvalue(), encoding="utf-8")
            print(f"  RECORD: {refreshed} line(s) refreshed, {dropped} dropped")


def _bom_refs(node) -> set[str]:
    """Every bom-ref defined anywhere inside ``node``."""
    refs: set[str] = set()
    if isinstance(node, dict):
        if isinstance(node.get("bom-ref"), str):
            refs.add(node["bom-ref"])
        for value in node.values():
            refs |= _bom_refs(value)
    elif isinstance(node, list):
        for value in node:
            refs |= _bom_refs(value)
    return refs


def inventory_view(document: dict) -> dict:
    """The SBOM without the parts that record how it was produced.

    ``metadata.tools`` and ``formulation`` describe the build environment of
    the upstream wheel, not the content of this image (see the module
    docstring), so a version named only there is neither present nor absent
    here. The tools' own dependency graph is recorded in ``dependencies``
    under the bom-refs defined in ``metadata.tools``, so those entries and
    edges go with them; every other dependency entry stays.
    """
    view = copy.deepcopy(document)
    view.pop("formulation", None)
    metadata = view.get("metadata")
    tools = metadata.pop("tools", None) if isinstance(metadata, dict) else None
    tool_refs = _bom_refs(tools)
    if tool_refs and isinstance(view.get("dependencies"), list):
        kept = []
        for entry in view["dependencies"]:
            if entry.get("ref") in tool_refs:
                continue
            if "dependsOn" in entry:
                entry["dependsOn"] = [
                    ref for ref in entry["dependsOn"] if ref not in tool_refs
                ]
            kept.append(entry)
        view["dependencies"] = kept
    return view


def verify(
    embed: pathlib.Path, site_packages: pathlib.Path, replacements: dict[str, str]
) -> None:
    """Fail the build if a removed version is still present or still declared.

    Only the surfaces that describe what the image contains are checked: the
    wheel files themselves, BUNDLE_SUPPORT, the CycloneDX SBOM and RECORD.

    Licence and attribution files such as THIRD-PARTY-NOTICES.md are
    deliberately excluded. They record the provenance of code virtualenv was
    distributed with and are not an inventory of what is installed; rewriting
    them would falsify an attribution record to satisfy a scanner that does
    not read them. The SBOM's ``metadata.tools`` and ``formulation`` are
    excluded for the same reason.
    """
    stale_versions = {removed.split("-", 2)[1] for removed in replacements}

    targets: list[pathlib.Path] = [embed / "__init__.py"]
    targets.extend(embed.glob("*.whl"))
    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        targets.extend(dist_info.glob("sboms/*.json"))
        record = dist_info / "RECORD"
        if record.exists():
            targets.append(record)

    for path in targets:
        if not path.is_file():
            continue

        # Wheels are zip archives, so only their file name carries a version.
        # Every other target is text and must be readable: a verification step
        # that cannot read what it is checking has to fail rather than report
        # success on the file name alone.
        haystack = path.name
        if path.suffix != ".whl":
            try:
                text = path.read_text(encoding="utf-8")
                if path.parent.name == "sboms":
                    text = json.dumps(inventory_view(json.loads(text)))
            except (OSError, ValueError) as error:
                sys.exit(
                    f"harden-virtualenv-seeds: cannot read {path} "
                    f"to verify it: {error}"
                )
            haystack += text

        for version in sorted(stale_versions):
            if version in haystack:
                sys.exit(
                    "harden-virtualenv-seeds: " f"{path} still references {version}"
                )
    print(
        "  verified: superseded versions gone from wheels, "
        "BUNDLE_SUPPORT, SBOM and RECORD"
    )


def _record_problems(
    site_packages: pathlib.Path, dist_info: pathlib.Path, wheels: dict
) -> list[str]:
    record = dist_info / "RECORD"
    if not record.exists():
        return []
    problems = []
    declared_wheels = set()
    for row in csv.reader(io.StringIO(record.read_text(encoding="utf-8"))):
        if not row:
            continue
        path = row[0]
        digest = row[1] if len(row) > 1 else ""
        size = row[2] if len(row) > 2 else ""
        if "/seed/wheels/embed/" in path and path.endswith(".whl"):
            declared_wheels.add(path.rsplit("/", 1)[-1])
        if not digest:
            continue  # bytecode and RECORD itself carry no hash by design
        target = site_packages / path
        if not target.is_file():
            problems.append(f"RECORD declares {path}, which is not on disk")
            continue
        data = target.read_bytes()
        if digest != _record_digest(data) or size != str(len(data)):
            problems.append(f"RECORD hash or size for {path} does not match the file")
    for name in sorted(set(wheels) - declared_wheels):
        problems.append(f"seed wheel {name} is on disk but missing from RECORD")
    return problems


def _sbom_problems(document: dict, wheels: dict) -> list[str]:
    problems = []
    declared = set()
    for component in document.get("components", []):
        name = _normalize(str(component.get("name", "")))
        version = component.get("version")
        wheel = next(
            (
                path
                for wheel_name, path in wheels.items()
                if _normalize(wheel_name.split("-", 1)[0]) == name
                and wheel_name.split("-", 2)[1] == version
            ),
            None,
        )
        if wheel is None:
            if _property(component, "virtualenv:bundled-wheel") is not None:
                problems.append(
                    f"declares seed wheel {component.get('name')} {version}, "
                    "which is not on disk"
                )
            continue
        declared.add(wheel.name)
        data = wheel.read_bytes()

        digests = set()
        for entry in component.get("hashes") or []:
            algorithm = SBOM_HASH_ALGORITHMS.get(entry.get("alg"))
            actual = algorithm(data).hexdigest() if algorithm else None
            digests.add(actual)
            if entry.get("content") != actual:
                problems.append(f"{entry.get('alg')} of {wheel.name} does not match")
        for identity in (component.get("evidence") or {}).get("identity") or []:
            for method in identity.get("methods") or []:
                if method.get("technique") == "hash-comparison" and (
                    method.get("value") not in digests
                ):
                    problems.append(f"hash evidence for {wheel.name} does not match")

        members = _wheel_members(wheel)
        by_name = dict(members)
        nested = component.get("components") or []
        files = {
            node.get("name"): node for node in nested if node.get("type") == "file"
        }
        if files:
            expected = {n: c for n, c in members if not WHEEL_OWN_RECORD.match(n)}
            for missing in sorted(set(files) - set(expected)):
                problems.append(
                    f"lists {missing} in {wheel.name}, which has no such file"
                )
            for unlisted in sorted(set(expected) - set(files)):
                problems.append(
                    f"{wheel.name} contains {unlisted}, which is not listed"
                )
            for member in sorted(set(files) & set(expected)):
                content = expected[member]
                for entry in files[member].get("hashes") or []:
                    algorithm = SBOM_HASH_ALGORITHMS.get(entry.get("alg"))
                    if (
                        not algorithm
                        or entry.get("content") != algorithm(content).hexdigest()
                    ):
                        problems.append(f"hash of {wheel.name}:{member} does not match")
                size = _property(files[member], "size")
                if size is not None and size != str(len(content)):
                    problems.append(f"size of {wheel.name}:{member} does not match")

        libraries = [node for node in nested if node.get("type") == "library"]
        for node in libraries:
            manifest = _property(node, "virtualenv:vendored-manifest")
            if manifest is None:
                continue
            content = by_name.get(manifest)
            on_disk = (
                None
                if content is None
                else _manifest_version(manifest, content, str(node.get("name", "")))
            )
            if on_disk != node.get("version"):
                problems.append(
                    f"declares {wheel.name} vendoring {node.get('name')} "
                    f"{node.get('version')}, but its {manifest} gives {on_disk}"
                )
        for manifest in sorted(
            {
                _property(node, "virtualenv:vendored-manifest") or ""
                for node in libraries
            }
        ):
            if not manifest.endswith("vendor.txt") or manifest not in by_name:
                continue
            listed = {
                _normalize(str(node.get("name", "")))
                for node in libraries
                if _property(node, "virtualenv:vendored-manifest") == manifest
            }
            pins = _parse_pins(by_name[manifest].decode("utf8", "ignore"))
            for pin in sorted(set(pins) - listed):
                problems.append(
                    f"{wheel.name} vendors {pin} {pins[pin]} ({manifest}), "
                    "which is not declared"
                )

    for name in sorted(set(wheels) - declared):
        problems.append(f"seed wheel {name} is on disk but not declared")
    return problems


def _wheel_interior_problems(wheel: pathlib.Path) -> list[str]:
    """What a seed wheel says about itself, checked against what it contains.

    Its own RECORD must list every member with the right hash and size; its
    bundled bom.cdx.json must agree with its vendor.txt in both directions and
    reference no component it does not declare; and it must not vendor any
    package in REMOVED_VENDORED, by directory or by vendor.txt pin.
    """
    problems = []
    dist = wheel.name.split("-", 1)[0]
    members = dict(_wheel_members(wheel))

    record_name = next((n for n in members if WHEEL_OWN_RECORD.match(n)), None)
    if record_name is None:
        # A wheel must carry its RECORD; without one nothing in it can be
        # verified, which is not the same as nothing being wrong.
        problems.append(f"{wheel.name}: has no RECORD")
    else:
        rows = [
            row
            for row in csv.reader(io.StringIO(members[record_name].decode("utf-8")))
            if row
        ]
        listed = {row[0] for row in rows}
        for path, digest, size in ((row + ["", ""])[:3] for row in rows):
            if not digest:
                continue
            content = members.get(path)
            if content is None:
                problems.append(f"{wheel.name}: RECORD lists {path}, which it lacks")
            elif digest != _record_digest(content) or size != str(len(content)):
                problems.append(f"{wheel.name}: RECORD hash or size for {path}")
        for path in sorted(set(members) - listed):
            problems.append(f"{wheel.name}: {path} is not in its RECORD")

    for package in sorted(REMOVED_VENDORED):
        if any(n.startswith(f"{dist}/_vendor/{package}/") for n in members):
            problems.append(f"{wheel.name} still vendors {package}")

    vendor_txt = members.get(f"{dist}/_vendor/vendor.txt")
    if vendor_txt is not None:
        pins = _parse_pins(vendor_txt.decode("utf8", "ignore"))
        for name in sorted(REMOVED_VENDORED.values()):
            if _normalize(name) in pins:
                problems.append(f"{wheel.name}: vendor.txt still pins {name}")
        bom_bytes = members.get(f"{dist}/_vendor/bom.cdx.json")
        if bom_bytes is not None:
            bom = json.loads(bom_bytes)
            declared = {}
            for component in bom.get("components", []):
                declared[_normalize(str(component.get("name", "")))] = component.get(
                    "version"
                )
            for name, version in sorted(pins.items()):
                if declared.get(name) != version:
                    problems.append(
                        f"{wheel.name}: bom.cdx.json gives {name} "
                        f"{declared.get(name)}, vendor.txt pins {version}"
                    )
            refs = _bom_refs(bom.get("components", [])) | _bom_refs(
                (bom.get("metadata") or {}).get("component")
            )
            for entry in bom.get("dependencies", []):
                for ref in [entry.get("ref")] + list(entry.get("dependsOn", [])):
                    if ref not in refs:
                        problems.append(
                            f"{wheel.name}: bom.cdx.json depends on {ref}, "
                            "which it does not declare"
                        )
    return problems


def verify_consistency(embed: pathlib.Path, site_packages: pathlib.Path) -> None:
    """Fail the build if the declared inventory disagrees with the bytes on disk.

    verify() proves removed versions are no longer named. This proves the
    inverse for what was kept: every RECORD hash and size matches its file,
    and the SBOM's hash, file list, file hashes and sizes, and vendored
    versions for each seed wheel match that wheel. Each seed wheel must also
    agree with itself and vendor nothing in REMOVED_VENDORED. Runs on every
    invocation, including the idempotency re-run, because it only reads.
    """
    wheels = {wheel.name: wheel for wheel in embed.glob("*.whl")}
    problems: list[str] = []
    for wheel in wheels.values():
        problems.extend(_wheel_interior_problems(wheel))
    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        problems.extend(_record_problems(site_packages, dist_info, wheels))
        for sbom_path in dist_info.glob("sboms/*.json"):
            try:
                document = json.loads(sbom_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                problems.append(f"cannot read {sbom_path}: {error}")
                continue
            problems.extend(
                f"{sbom_path.name} {problem}"
                for problem in _sbom_problems(document, wheels)
            )
    if problems:
        sys.exit(
            "harden-virtualenv-seeds: the declared inventory disagrees with the "
            "files on disk:\n" + "\n".join(f"  {problem}" for problem in problems)
        )
    print(
        "  verified: RECORD and SBOM hashes, sizes, file lists and vendored "
        "versions match the seed wheels on disk"
    )


def harden_distro_wheels() -> None:
    """Apply REMOVED_VENDORED to the wheels that "python -m venv" installs.

    ensurepip seeds every "python -m venv" environment from DISTRO_WHEEL_DIR,
    so the pip wheel there hands each one the pkg_resources the installed pip
    was hardened to drop, exactly as virtualenv's seed wheel did. Same removal,
    same self-check.

    The wheel belongs to the distribution's py3-pip-wheel package. Its SPDX
    document names pip, urllib3 and msgpack with no file checksum and does not
    mention setuptools or pkg_resources, so removing them leaves that document
    accurate. apk's own file database will report the wheel as modified, which
    is true.

    Must run after ensurepip has installed pip from this wheel and
    harden-pip-vendor.py has hardened that install - it expects pkg_resources
    to be there - and as the owner of DISTRO_WHEEL_DIR.
    """
    if not DISTRO_WHEEL_DIR.is_dir():
        print(f"harden-virtualenv-seeds: no {DISTRO_WHEEL_DIR}; nothing to harden")
        return
    print(f"harden-virtualenv-seeds: hardening {DISTRO_WHEEL_DIR}")
    stripped = strip_removed_vendored(DISTRO_WHEEL_DIR, set())
    if not stripped:
        print(f"  no distro wheel vendors {', '.join(sorted(REMOVED_VENDORED))}")
    problems = []
    for wheel in sorted(DISTRO_WHEEL_DIR.glob("*.whl")):
        problems.extend(_wheel_interior_problems(wheel))
    if problems:
        sys.exit(
            "harden-virtualenv-seeds: a distro wheel disagrees with itself or "
            "still vendors a removed package:\n"
            + "\n".join(f"  {problem}" for problem in problems)
        )
    print(
        "  verified: every distro wheel agrees with its own RECORD and "
        "bom.cdx.json and vendors nothing in REMOVED_VENDORED"
    )
    print("harden-virtualenv-seeds: done")


def main() -> None:
    arguments = sys.argv[1:]
    if arguments == ["--distro-wheels"]:
        harden_distro_wheels()
        return
    if arguments:
        sys.exit("usage: harden-virtualenv-seeds.py [--distro-wheels]")

    embed = find_embed()
    site_packages = embed.parents[3]
    print(f"harden-virtualenv-seeds: hardening {embed}")
    touched: Touched = set()

    replacements = remove_superseded(embed, touched)
    if replacements:
        rewrite_bundle_support(embed, replacements, touched)
        rewrite_inventory(site_packages, replacements, touched)
    else:
        print("  nothing superseded")

    # Runs regardless of the above: the wheel that survives deduplication is
    # still upstream's build, and that is the one carrying the vulnerable
    # vendored code. Keeping this outside the early return is deliberate.
    replaced = replace_with_distro_wheels(embed, touched)
    if not replaced:
        print("  bundled wheels are not behind the distro wheels")

    # After the swap, so a distro wheel that still vendors a removed package is
    # stripped too, and before the integrity records, which must describe the
    # final bytes of every wheel either step rewrote.
    stripped = strip_removed_vendored(embed, touched)
    if not stripped:
        print(f"  no seed wheel vendors {', '.join(sorted(REMOVED_VENDORED))}")

    rewritten = sorted(set(replaced) | set(stripped))
    if rewritten:
        rewrite_bundle_sha256(embed, rewritten, touched)
        refresh_sbom_for_replaced(site_packages, embed, rewritten, touched)

    # Last write: RECORD hashes the final bytes of everything changed above,
    # the SBOM included.
    refresh_record(site_packages, touched)

    if replacements:
        verify(embed, site_packages, replacements)
    verify_consistency(embed, site_packages)

    print("harden-virtualenv-seeds: done")


if __name__ == "__main__":
    main()
