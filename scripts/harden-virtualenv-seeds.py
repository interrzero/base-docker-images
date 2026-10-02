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
"""

from __future__ import annotations

import base64
import hashlib
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


def remove_superseded(embed: pathlib.Path) -> dict[str, str]:
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
    return replacements


def rewrite_bundle_support(embed: pathlib.Path, replacements: dict[str, str]) -> None:
    """Point BUNDLE_SUPPORT at the wheels that are still present."""
    init = embed / "__init__.py"
    original = init.read_text(encoding="utf-8")
    updated = original
    for removed, kept in replacements.items():
        updated = updated.replace(removed, kept)
    if updated != original:
        init.write_text(updated, encoding="utf-8")
        print("  BUNDLE_SUPPORT re-pointed")
    for cached in embed.glob("__pycache__/*.pyc"):
        cached.unlink()


def rewrite_inventory(
    site_packages: pathlib.Path, replacements: dict[str, str]
) -> None:
    """Drop the removed wheels from the shipped CycloneDX SBOM and RECORD.

    These are what scanners read as the inventory, which is why the finding
    reports no file path. The components are REMOVED rather than relabelled:
    the image no longer contains those versions at all, so deleting the entry
    is the accurate description. Rewriting a version in place would instead
    leave a duplicate component and dangling bom-ref, purl and dependency
    references pointing at a package that is not there.
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
            print(f"  {sbom_path.name}: {dropped} component(s) removed")

        record = dist_info / "RECORD"
        if not record.exists():
            continue
        original = record.read_text(encoding="utf-8")
        kept_lines = [
            line
            for line in original.splitlines(keepends=True)
            if not any(removed in line for removed in replacements)
        ]
        if len(kept_lines) != len(original.splitlines(keepends=True)):
            record.write_text("".join(kept_lines), encoding="utf-8")
            print("  RECORD: removed wheel entries dropped")


def _vendored_pins(wheel: pathlib.Path, dist: str) -> dict[str, str]:
    """name -> version from <dist>/_vendor/vendor.txt inside a wheel."""
    pins: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith(f"{dist}/") and name.endswith("_vendor/vendor.txt"):
                text = archive.read(name).decode("utf8", "ignore")
                for raw in text.splitlines():
                    line = raw.split("#", 1)[0].strip()
                    match = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,]+)", line)
                    if match:
                        key = re.sub(r"[-_.]+", "-", match.group(1)).lower()
                        pins[key] = match.group(2)
    return pins


def _version_tuple(value: str) -> tuple:
    return tuple(int(part) for part in re.findall(r"\d+", value)[:4])


def replace_with_distro_wheels(
    embed: pathlib.Path,
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
        for name, bundled_version in bundled_pins.items():
            distro_version = distro_pins.get(name)
            if distro_version is None or distro_version == bundled_version:
                continue
            try:
                is_behind = _version_tuple(bundled_version) < _version_tuple(
                    distro_version
                )
            except ValueError:
                is_behind = False
            if is_behind:
                behind[name] = (bundled_version, distro_version)

        if not behind:
            continue

        shutil.copyfile(distro, wheel)
        replaced[wheel.name] = behind
        for dep, (was, now) in sorted(behind.items()):
            print(f"  {wheel.name}: {dep} {was} -> {now} (from the distro wheel)")

    return replaced


def rewrite_bundle_sha256(embed: pathlib.Path, replaced: dict) -> None:
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
    # Stale bytecode would re-assert the old hash and the check would still fail.
    for cached in embed.glob("__pycache__/*.pyc"):
        cached.unlink()


def _record_line(site_packages: pathlib.Path, target: pathlib.Path) -> str:
    data = target.read_bytes()
    digest = (
        base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    )
    rel = target.relative_to(site_packages).as_posix()
    return f"{rel},sha256={digest},{len(data)}"


def refresh_record_and_sbom(
    site_packages: pathlib.Path, embed: pathlib.Path, replaced: dict
) -> None:
    """Make the declared inventory describe the wheels we just swapped in."""
    if not replaced:
        return

    changed = [embed / name for name in replaced] + [embed / "__init__.py"]

    for dist_info in site_packages.glob("virtualenv-*.dist-info"):
        record = dist_info / "RECORD"
        if record.exists():
            by_path = {
                target.relative_to(site_packages).as_posix(): _record_line(
                    site_packages, target
                )
                for target in changed
                if target.is_file()
            }
            lines = []
            for line in record.read_text(encoding="utf-8").splitlines():
                key = line.split(",", 1)[0]
                lines.append(by_path.pop(key, line))
            record.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"  RECORD refreshed for {len(changed) - len(by_path)} file(s)")

        # The CycloneDX SBOM records the vendored dependencies of each bundled
        # wheel, so it names the versions we just replaced.
        for sbom_path in dist_info.glob("sboms/*.json"):
            text = sbom_path.read_text(encoding="utf-8")
            original = text
            for deps in replaced.values():
                for dep, (was, now) in deps.items():
                    text = text.replace(
                        f"pkg:pypi/{dep}@{was}", f"pkg:pypi/{dep}@{now}"
                    )
            if text == original:
                continue
            document = json.loads(text)

            def _fix(node) -> None:
                if isinstance(node, dict):
                    name = re.sub(r"[-_.]+", "-", str(node.get("name", ""))).lower()
                    for deps in replaced.values():
                        if name in deps and node.get("version") == deps[name][0]:
                            node["version"] = deps[name][1]
                    for value in node.values():
                        _fix(value)
                elif isinstance(node, list):
                    for value in node:
                        _fix(value)

            _fix(document)
            sbom_path.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )
            print(f"  {sbom_path.name}: vendored dependency versions corrected")


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
    not read them.
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
                haystack += path.read_text(encoding="utf-8")
            except OSError as error:
                sys.exit(
                    f"harden-virtualenv-seeds: cannot read {path} "
                    f"to verify it: {error}"
                )

        for version in sorted(stale_versions):
            if version in haystack:
                sys.exit(
                    "harden-virtualenv-seeds: " f"{path} still references {version}"
                )
    print(
        "  verified: superseded versions gone from wheels, "
        "BUNDLE_SUPPORT, SBOM and RECORD"
    )


def main() -> None:
    embed = find_embed()
    site_packages = embed.parents[3]
    print(f"harden-virtualenv-seeds: hardening {embed}")

    replacements = remove_superseded(embed)
    if replacements:
        rewrite_bundle_support(embed, replacements)
        rewrite_inventory(site_packages, replacements)
        verify(embed, site_packages, replacements)
    else:
        print("  nothing superseded")

    # Runs regardless of the above: the wheel that survives deduplication is
    # still upstream's build, and that is the one carrying the vulnerable
    # vendored code. Keeping this outside the early return is deliberate.
    replaced = replace_with_distro_wheels(embed)
    if replaced:
        rewrite_bundle_sha256(embed, replaced)
        refresh_record_and_sbom(site_packages, embed, replaced)
    else:
        print("  bundled wheels are not behind the distro wheels")

    print("harden-virtualenv-seeds: done")


if __name__ == "__main__":
    main()
