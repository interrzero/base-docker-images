#!/usr/bin/env python3
"""Raise pip's bundled dependencies to their fixed versions.

pip ships copies of several third-party packages under ``pip/_vendor`` and
records their provenance in ``pip/_vendor/vendor.txt`` and
``pip/_vendor/bom.cdx.json``. Scanners parse both files as an inventory of
installed packages, so pip's bundled copies surface as image vulnerabilities.

Two advisories currently apply, and both are resolved here by changing the
code that is actually present rather than by suppressing the finding:

  msgpack 1.1.2 -> 1.2.1
      GHSA-6v7p-g79w-8964. Replaced with the pure-Python sources of the
      already-installed msgpack, which sits in site-packages at a fixed
      version as a transitive dependency of poetry via cachecontrol.

  pkg_resources -> removed
      CVE-2025-47273 (fixed in setuptools 78.1.1) and CVE-2026-59890 (fixed
      in setuptools 83.0.0). setuptools deleted pkg_resources outright in
      82.0.0, so there is no release that both ships the module and carries
      both fixes; upstream's fixed state is removal. pip imports it only
      from the pkg_resources metadata backend, which cannot be selected on
      Python 3.14+ and is deprecated on earlier versions
      (see pip/_internal/metadata/__init__.py::_should_use_importlib_metadata).

The script is deliberately strict: any unexpected layout aborts the build
rather than silently leaving a vulnerable copy in the image.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import sys

MSGPACK_MIN = (1, 2, 1)
MSGPACK_MODULES = ("__init__.py", "exceptions.py", "ext.py", "fallback.py")


def fail(message: str) -> None:
    sys.exit(f"harden-pip-vendor: {message}")


def find_vendor_dir() -> pathlib.Path:
    import pip

    vendor = pathlib.Path(pip.__file__).resolve().parent / "_vendor"
    if not vendor.is_dir():
        fail(f"expected pip vendor directory at {vendor}")
    return vendor


def find_installed_msgpack() -> pathlib.Path:
    """Locate the real msgpack install, skipping pip's bundled copy."""
    import importlib.util

    spec = importlib.util.find_spec("msgpack")
    if spec is None or not spec.origin:
        fail("msgpack is not installed; cannot source fixed sources from it")
    src = pathlib.Path(spec.origin).resolve().parent
    if "_vendor" in src.parts:
        fail(f"resolved msgpack to pip's bundled copy at {src}")
    return src


def replace_vendored_msgpack(vendor: pathlib.Path) -> str:
    import msgpack

    if msgpack.version < MSGPACK_MIN:
        fail(
            f"installed msgpack {msgpack.__version__} is below the fixed "
            f"version {'.'.join(str(p) for p in MSGPACK_MIN)}"
        )

    src = find_installed_msgpack()
    dst = vendor / "msgpack"
    if not dst.is_dir():
        fail(f"expected bundled msgpack at {dst}")

    for name in MSGPACK_MODULES:
        origin = src / name
        if not origin.is_file():
            fail(f"missing {origin} in the installed msgpack")
        shutil.copyfile(origin, dst / name)

    # The compiled extension is deliberately not copied: pip's bundled copy
    # has always run the pure-Python fallback, and a .so would not be
    # importable under pip's vendored module path.
    shutil.rmtree(dst / "__pycache__", ignore_errors=True)
    return msgpack.__version__


def remove_vendored_pkg_resources(vendor: pathlib.Path) -> None:
    target = vendor / "pkg_resources"
    if not target.is_dir():
        fail(f"expected bundled pkg_resources at {target}")
    shutil.rmtree(target)


def rewrite_vendor_txt(vendor: pathlib.Path, msgpack_version: str) -> None:
    path = vendor / "vendor.txt"
    if not path.is_file():
        fail(f"expected {path}")

    kept: list[str] = []
    saw_msgpack = saw_setuptools = False
    for line in path.read_text().splitlines():
        name = line.strip().split("==")[0].strip().lower()
        if name == "msgpack":
            saw_msgpack = True
            kept.append(f"msgpack=={msgpack_version}")
        elif name == "setuptools":
            saw_setuptools = True
        else:
            kept.append(line)

    if not saw_msgpack:
        fail(f"no msgpack entry found in {path}")
    if not saw_setuptools:
        fail(f"no setuptools entry found in {path}")
    path.write_text("\n".join(kept) + "\n")


def rewrite_bom(vendor: pathlib.Path, msgpack_version: str) -> None:
    path = vendor / "bom.cdx.json"
    if not path.is_file():
        # Older pip releases predate the bundled CycloneDX BOM.
        return

    bom = json.loads(path.read_text())
    components = bom.get("components")
    if not isinstance(components, list):
        fail(f"unexpected structure in {path}: no components list")

    kept = []
    saw_msgpack = saw_setuptools = False
    for component in components:
        name = str(component.get("name", "")).lower()
        if name == "msgpack":
            saw_msgpack = True
            component["version"] = msgpack_version
            purl = component.get("purl")
            if isinstance(purl, str) and "@" in purl:
                component["purl"] = f"{purl.split('@', 1)[0]}@{msgpack_version}"
            kept.append(component)
        elif name == "setuptools":
            saw_setuptools = True
        else:
            kept.append(component)

    if not saw_msgpack:
        fail(f"no msgpack component found in {path}")
    if not saw_setuptools:
        fail(f"no setuptools component found in {path}")

    bom["components"] = kept
    path.write_text(json.dumps(bom, indent=2) + "\n")


def _normalize(name: str) -> str:
    """PEP 503 normalisation, so typing_extensions and typing-extensions match."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def read_vendor_pins(vendor: pathlib.Path) -> dict[str, str]:
    """name -> version, from pip's own vendor.txt.

    vendor.txt is the authority for what pip actually vendors. It is written by
    pip's vendoring tool from the tree it just installed, whereas bom.cdx.json
    is generated separately and has been observed disagreeing with it (see
    reconcile_bom_with_pins). Lines may carry comments or environment markers.
    """
    path = vendor / "vendor.txt"
    if not path.is_file():
        fail(f"expected {path}")

    pins: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;,]+)", line)
        if match:
            pins[_normalize(match.group(1))] = match.group(2)
    if not pins:
        fail(f"no pinned versions parsed from {path}; refusing to reconcile blind")
    return pins


def reconcile_bom_with_pins(vendor: pathlib.Path) -> list[tuple[str, str, str]]:
    """Correct any bom.cdx.json component that disagrees with vendor.txt.

    pip ships a CycloneDX BOM of its vendored dependencies, and scanners read it
    as the inventory of what is installed. It can disagree with what pip
    actually bundles: verified on pip 26.2.1, which vendors urllib3 2.8.0
    (pip/_vendor/urllib3/_version.py and vendor.txt both say 2.8.0) while
    bom.cdx.json still declared 2.7.0. Trivy reported the three urllib3 CVEs
    fixed in 2.8.0 against an image that did not contain the vulnerable code,
    with PkgPath null because the finding came from that declaration rather than
    from any file, and the publish gate blocked every python image for two days.

    This is deliberately generic rather than a list of named packages. It asks
    only "does the declaration match the pin", so the next package pip
    misdeclares is corrected with no edit here. A component with no vendor.txt
    pin is left untouched - absence of a pin is not evidence of a wrong version.

    Idempotent: a BOM that already agrees is rewritten byte-identically, so
    running twice changes nothing.
    """
    path = vendor / "bom.cdx.json"
    if not path.is_file():
        # Older pip releases predate the bundled CycloneDX BOM.
        return []

    pins = read_vendor_pins(vendor)
    try:
        bom = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        fail(f"{path} is not valid JSON: {error}")

    components = bom.get("components")
    if not isinstance(components, list):
        fail(f"unexpected structure in {path}: no components list")

    corrected: list[tuple[str, str, str]] = []
    purl_swaps: dict[str, str] = {}
    for component in components:
        name = str(component.get("name", ""))
        declared = str(component.get("version", ""))
        actual = pins.get(_normalize(name))
        if actual is None or declared == actual:
            continue

        component["version"] = actual
        purl = component.get("purl")
        if isinstance(purl, str) and "@" in purl:
            purl_swaps[purl] = f"{purl.split('@', 1)[0]}@{actual}"
        corrected.append((name, declared, actual))

    if purl_swaps:
        # The stale purl also appears in bom-ref and in the dependencies graph
        # (ref and dependsOn), and bom-ref embeds it in a decorated form such as
        # "pkg:pypi/pip@26.2.1#vendored/pkg:pypi/urllib3@2.7.0". Substituting on
        # the serialised document fixes every occurrence at once; a purl is
        # specific enough that this cannot collide with another component.
        text = json.dumps(bom, indent=2)
        for old, new in purl_swaps.items():
            text = text.replace(old, new)
        bom = json.loads(text)

    path.write_text(json.dumps(bom, indent=2) + "\n")
    return corrected


def verify_bom_agrees(vendor: pathlib.Path) -> None:
    """Fail if any BOM component still disagrees with vendor.txt."""
    path = vendor / "bom.cdx.json"
    if not path.is_file():
        return
    pins = read_vendor_pins(vendor)
    bad = []
    for component in json.loads(path.read_text()).get("components", []):
        name = str(component.get("name", ""))
        declared = str(component.get("version", ""))
        actual = pins.get(_normalize(name))
        if actual is not None and declared != actual:
            bad.append(f"{name} declared {declared}, pinned {actual}")
    if bad:
        fail("bom.cdx.json still disagrees with vendor.txt: " + "; ".join(bad))


def verify_corrections_against_disk(
    corrected: list[tuple[str, str, str]],
) -> None:
    """Confirm each corrected version matches the module actually importable.

    reconcile_bom_with_pins trusts vendor.txt, so this closes the loop: if
    vendor.txt were itself wrong, the reconcile would propagate that into the
    BOM and the image would still misreport its contents. Verified useful - on
    pip 26.2.1 the BOM declared urllib3 2.7.0 and idna 3.18 while the importable
    modules were 2.8.0 and 3.15, so the BOM was wrong in BOTH directions and
    vendor.txt matched disk for both.

    A vendored module exposing no __version__ is reported and skipped rather
    than failed: absence of the attribute is a convention difference, not
    evidence of a wrong version.
    """
    if not corrected:
        return

    import subprocess

    for name, _was, now in corrected:
        module = name.replace("-", "_")
        snippet = (
            f"import pip._vendor.{module} as m; "
            "import sys; "
            "v = getattr(m, '__version__', None); "
            "sys.stdout.write('' if v is None else str(v))"
        )
        result = subprocess.run(
            [sys.executable, "-c", snippet], capture_output=True, text=True
        )
        if result.returncode != 0:
            fail(
                f"corrected {name} to {now} but pip._vendor.{module} does not "
                f"import: {result.stderr.strip()}"
            )
        on_disk = result.stdout.strip()
        if not on_disk:
            print(f"  note: {name} exposes no __version__, disk check skipped")
            continue
        if on_disk != now:
            fail(
                f"vendor.txt pins {name}=={now} but the importable module is "
                f"{on_disk}; refusing to write a declaration that disagrees "
                f"with the code on disk"
            )
        print(f"  ok: {name} {now} confirmed against the importable module")


def verify(vendor: pathlib.Path, msgpack_version: str) -> None:
    """Confirm the result imports and reports the fixed version."""
    import subprocess

    checks = [
        (
            "bundled msgpack version",
            "import pip._vendor.msgpack as m; "
            f"assert m.__version__ == {msgpack_version!r}, m.__version__",
        ),
        (
            "pip cachecontrol serializer",
            "from pip._vendor.cachecontrol.serialize import Serializer; Serializer()",
        ),
        (
            "pip metadata backend",
            "from pip._internal.metadata import select_backend; "
            "assert select_backend().NAME == 'importlib', select_backend().NAME",
        ),
        (
            "bundled pkg_resources gone",
            "import importlib.util as u; "
            "assert u.find_spec('pip._vendor.pkg_resources') is None",
        ),
    ]
    for label, snippet in checks:
        result = subprocess.run(
            [sys.executable, "-c", snippet], capture_output=True, text=True
        )
        if result.returncode != 0:
            fail(f"verification failed ({label}): {result.stderr.strip()}")
        print(f"  ok: {label}")

    if (vendor / "pkg_resources").exists():
        fail("pkg_resources directory still present after removal")


def main() -> None:
    vendor = find_vendor_dir()
    print(f"harden-pip-vendor: hardening {vendor}")

    msgpack_version = replace_vendored_msgpack(vendor)
    print(f"  bundled msgpack raised to {msgpack_version}")

    remove_vendored_pkg_resources(vendor)
    print("  bundled pkg_resources removed (setuptools dropped it in 82.0.0)")

    rewrite_vendor_txt(vendor, msgpack_version)
    rewrite_bom(vendor, msgpack_version)
    print("  vendor.txt and bom.cdx.json updated")

    # Must run after the rewrites above, so vendor.txt already carries the
    # corrected msgpack pin and is a trustworthy authority here.
    corrected = reconcile_bom_with_pins(vendor)
    for name, was, now in corrected:
        print(f"  bom.cdx.json corrected: {name} {was} -> {now} (per vendor.txt)")
    if not corrected:
        print("  bom.cdx.json already agrees with vendor.txt")

    verify_corrections_against_disk(corrected)

    verify(vendor, msgpack_version)
    verify_bom_agrees(vendor)
    print("  ok: bom.cdx.json agrees with vendor.txt")
    print("harden-pip-vendor: done")


if __name__ == "__main__":
    main()
