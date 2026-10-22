"""Tests for scripts/harden-virtualenv-seeds.py.

The fixture is a site-packages laid out the way virtualenv 21.14.12 installs:
two pip and two setuptools seed wheels, a RECORD with a sha256 and size for
each file, and a CycloneDX SBOM that declares every seed wheel with its hash,
the hash and size of every file inside it, and the packages it vendors. Its
``metadata.tools`` records the build environment of the upstream wheel, which
names setuptools 84.0.0 while the bundled setuptools is 84.2.1 - the shape that
first appeared in 21.14.12.

The assertions re-derive everything from the bytes on disk with their own code
rather than calling the script's verification, so a defect in that
verification cannot make these tests pass.

Run: python3 -m unittest discover -s tests/scripts -v
"""

from __future__ import annotations

import base64
import contextlib
import copy
import csv
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import unittest.mock
import zipfile

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[2]
    / "scripts"
    / "harden-virtualenv-seeds.py"
)

VIRTUALENV = "21.14.12"
EMBED = "virtualenv/seed/wheels/embed"


def load_script():
    spec = importlib.util.spec_from_file_location("harden_virtualenv_seeds", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_digest(data: bytes) -> str:
    return (
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    )


def make_wheel(path: pathlib.Path, dist: str, version: str, files: dict) -> None:
    """A wheel whose own RECORD lists every member, as real wheels do."""
    record = f"{dist}-{version}.dist-info/RECORD"
    rows = [[name, record_digest(data), str(len(data))] for name, data in files.items()]
    rows.append([record, "", ""])
    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(rows)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr(record, out.getvalue())


def pip_bom(version: str, pins: dict) -> bytes:
    """pip's own bom.cdx.json: pip, every vendored pin, and their graph."""
    refs = {name: f"pkg:pypi/{name}@{pinned}" for name, pinned in pins.items()}
    components = [
        {"name": "pip", "version": version, "bom-ref": f"pkg:pypi/pip@{version}"}
    ]
    components += [
        {
            "type": "library",
            "name": name,
            "version": pinned,
            "bom-ref": refs[name],
            "purl": refs[name],
        }
        for name, pinned in pins.items()
    ]
    document = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"bom-ref": "bom-ref:pip", "name": "pip"}},
        "components": components,
        "dependencies": [{"ref": "bom-ref:pip", "dependsOn": list(refs.values())}]
        + [{"ref": ref} for ref in refs.values()],
    }
    return (json.dumps(document, indent=2) + "\n").encode()


def pip_files(
    version: str,
    urllib3: str,
    msgpack: str,
    certifi: str = "2026.10.19",
    extra: dict | None = None,
    pkg_resources: bool = True,
):
    pins = {
        "urllib3": urllib3,
        "msgpack": msgpack,
        "certifi": certifi,
    }
    if pkg_resources:
        pins["setuptools"] = "70.3.0"
    files = {
        "pip/__init__.py": f'__version__ = "{version}"\n'.encode(),
        "pip/_vendor/vendor.txt": "".join(
            f"{name}=={pinned}\n" for name, pinned in pins.items()
        ).encode(),
        "pip/_vendor/bom.cdx.json": pip_bom(version, pins),
        "pip/_vendor/urllib3/_version.py": f'__version__ = "{urllib3}"\n'.encode(),
        "pip/_vendor/msgpack/__init__.py": f'version = "{msgpack}"\n'.encode(),
        "pip/_vendor/certifi/__init__.py": f'__version__ = "{certifi}"\n'.encode(),
        f"pip-{version}.dist-info/METADATA": (
            f"Metadata-Version: 2.4\nName: pip\nVersion: {version}\n\n"
        ).encode(),
    }
    if pkg_resources:
        # What harden-pip-vendor.py removes from the installed pip.
        files["pip/_vendor/pkg_resources/__init__.py"] = b"# vendored 70.3.0\n"
        files["pip/_vendor/pkg_resources/py.typed"] = b""
    files.update(extra or {})
    return files


def setuptools_files(version: str) -> dict:
    return {
        "setuptools/__init__.py": f'__version__ = "{version}"\n'.encode(),
        "setuptools/_vendor/zipp-3.23.0.dist-info/METADATA": (
            b"Metadata-Version: 2.1\nName: zipp\nVersion: 3.23.0\n\nzipp\n"
        ),
        "setuptools/_vendor/zipp/__init__.py": b"",
        f"setuptools-{version}.dist-info/METADATA": (
            f"Metadata-Version: 2.4\nName: setuptools\nVersion: {version}\n\n"
        ).encode(),
    }


def wheel_component(wheel: pathlib.Path) -> dict:
    """A component in the form virtualenv's own SBOM generator emits."""
    dist, version = wheel.name.split("-", 2)[:2]
    ref = f"pkg:pypi/{dist}@{version}"
    data = wheel.read_bytes()
    nested = []
    libraries = []
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            if info.filename.endswith(".dist-info/RECORD"):
                continue
            content = archive.read(info)
            nested.append(
                {
                    "type": "file",
                    "bom-ref": f"{ref}#{info.filename}",
                    "name": info.filename,
                    "hashes": [{"alg": "SHA-256", "content": sha256(content)}],
                    "properties": [{"name": "size", "value": str(len(content))}],
                }
            )
            if info.filename == f"{dist}/_vendor/vendor.txt":
                for line in content.decode().splitlines():
                    name, pinned = line.split("==")
                    libraries.append((name, pinned, info.filename))
            elif info.filename.endswith(".dist-info/METADATA") and "/_vendor/" in (
                info.filename
            ):
                fields = dict(
                    line.split(": ", 1)
                    for line in content.decode().split("\n\n")[0].splitlines()
                )
                libraries.append((fields["Name"], fields["Version"], info.filename))
    for name, pinned, manifest in libraries:
        nested.append(
            {
                "type": "library",
                "bom-ref": f"{ref}#vendored/pkg:pypi/{name}@{pinned}",
                "name": name,
                "version": pinned,
                "purl": f"pkg:pypi/{name}@{pinned}",
                "properties": [
                    {"name": "virtualenv:vendored-manifest", "value": manifest}
                ],
            }
        )
    return {
        "type": "library",
        "bom-ref": ref,
        "name": dist,
        "version": version,
        "purl": ref,
        "properties": [
            {
                "name": "virtualenv:bundled-wheel",
                "value": f"src/{EMBED}/{wheel.name}",
            }
        ],
        "hashes": [{"alg": "SHA-256", "content": sha256(data)}],
        "evidence": {
            "identity": [
                {
                    "field": "hash",
                    "methods": [
                        {"technique": "hash-comparison", "value": sha256(data)}
                    ],
                }
            ]
        },
        "components": nested,
    }


def build_tool(name: str, version: str) -> dict:
    ref = f"tool:pkg:pypi/{name}@{version}"
    return {
        "type": "library",
        "bom-ref": ref,
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
        "components": [
            {
                "type": "file",
                "bom-ref": f"{ref}#{name}-{version}.dist-info/{part}",
                "name": f"{name}-{version}.dist-info/{part}",
            }
            for part in ("METADATA", "WHEEL", "top_level.txt")
        ],
    }


def wheel_members(wheel: pathlib.Path) -> dict:
    with zipfile.ZipFile(wheel) as archive:
        return {
            i.filename: archive.read(i) for i in archive.infolist() if not i.is_dir()
        }


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Fixture:
    """A temporary install of virtualenv with its seed wheels and inventory."""

    def __init__(
        self,
        root: pathlib.Path,
        tool_versions=("84.0.0",),
        distro_certifi="2026.10.19",
        distro_without=(),
        distro_has_pkg_resources=True,
    ):
        self.lib = root / "lib"
        self.site = self.lib / "python3.14" / "site-packages"
        self.embed = self.site / EMBED
        self.dist_info = self.site / f"virtualenv-{VIRTUALENV}.dist-info"
        self.sbom = self.dist_info / "sboms" / "virtualenv.cdx.json"
        self.record = self.dist_info / "RECORD"
        self.distro = root / "python-wheels"
        self.embed.mkdir(parents=True)
        self.sbom.parent.mkdir(parents=True)
        self.distro.mkdir()

        make_wheel(
            self.embed / "pip-26.0.1-py3-none-any.whl",
            "pip",
            "26.0.1",
            pip_files("26.0.1", "2.6.3", "1.1.1"),
        )
        make_wheel(
            self.embed / "pip-26.2.2-py3-none-any.whl",
            "pip",
            "26.2.2",
            pip_files("26.2.2", "2.7.0", "1.1.2"),
        )
        make_wheel(
            self.embed / "setuptools-82.0.1-py3-none-any.whl",
            "setuptools",
            "82.0.1",
            setuptools_files("82.0.1"),
        )
        make_wheel(
            self.embed / "setuptools-84.2.1-py3-none-any.whl",
            "setuptools",
            "84.2.1",
            setuptools_files("84.2.1"),
        )

        # The distribution's build of the same pip: patched urllib3 and msgpack,
        # one file it adds, one it no longer ships, and type stubs - including
        # pkg_resources.pyi, which the installed hardening keeps.
        patched = pip_files(
            "26.2.2",
            "2.8.0",
            "1.2.1",
            certifi=distro_certifi,
            pkg_resources=distro_has_pkg_resources,
            extra={
                "pip/_vendor/urllib3/contrib/pyopenssl.py.orig": b"orig\n",
                "pip/_vendor/pkg_resources.pyi": b"",
                "pip/_vendor/msgpack.pyi": b"",
            },
        )
        del patched["pip/_vendor/certifi/__init__.py"]
        patched["pip/_vendor/certifi/core.py"] = b"# distro layout\n"
        for name in distro_without:
            vendor_txt = patched["pip/_vendor/vendor.txt"].decode()
            patched["pip/_vendor/vendor.txt"] = "".join(
                line + "\n"
                for line in vendor_txt.splitlines()
                if not line.startswith(f"{name}==")
            ).encode()
        make_wheel(
            self.distro / "pip-26.2.2-py3-none-any.whl", "pip", "26.2.2", patched
        )

        wheels = sorted(self.embed.glob("*.whl"))
        (self.embed / "__init__.py").write_text(
            "BUNDLE_SUPPORT = {\n"
            '    "3.14": {"pip": "pip-26.2.2-py3-none-any.whl",'
            ' "setuptools": "setuptools-84.2.1-py3-none-any.whl"},\n'
            '    "3.8": {"pip": "pip-26.0.1-py3-none-any.whl",'
            ' "setuptools": "setuptools-82.0.1-py3-none-any.whl"},\n'
            "}\n"
            "BUNDLE_SHA256 = {\n"
            + "".join(f'    "{w.name}": "{sha256(w.read_bytes())}",\n' for w in wheels)
            + "}\n",
            encoding="utf-8",
        )

        components = [wheel_component(w) for w in wheels]
        tools = [build_tool("hatchling", "1.32.4")] + [
            build_tool("setuptools", version) for version in tool_versions
        ]
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": {
                    "type": "library",
                    "bom-ref": f"pkg:pypi/virtualenv@{VIRTUALENV}",
                    "name": "virtualenv",
                    "version": VIRTUALENV,
                },
                "tools": {"components": tools},
            },
            "components": components,
            "dependencies": [
                {
                    "ref": f"pkg:pypi/virtualenv@{VIRTUALENV}",
                    "dependsOn": [c["bom-ref"] for c in components],
                }
            ]
            + [
                {
                    "ref": c["bom-ref"],
                    "dependsOn": [
                        n["bom-ref"] for n in c["components"] if n["type"] == "library"
                    ],
                }
                for c in components
            ]
            + [{"ref": t["bom-ref"], "dependsOn": []} for t in tools],
            "compositions": [
                {
                    "aggregate": "incomplete",
                    "dependencies": [f"pkg:pypi/virtualenv@{VIRTUALENV}"],
                }
            ],
            "formulation": [
                {
                    "bom-ref": "formula:wheel-build",
                    "workflows": [
                        {
                            "bom-ref": "workflow:wheel-build",
                            "resourceReferences": [
                                {"ref": t["bom-ref"]} for t in tools
                            ],
                        }
                    ],
                }
            ],
        }
        self.sbom.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

        rows = []
        for path in sorted(self.site.rglob("*")):
            if path.is_file() and path != self.record:
                rel = path.relative_to(self.site).as_posix()
                data = path.read_bytes()
                rows.append([rel, record_digest(data), str(len(data))])
        rows.append([f"{EMBED}/__pycache__/__init__.cpython-314.pyc", "", ""])
        rows.append([self.record.relative_to(self.site).as_posix(), "", ""])
        out = io.StringIO()
        csv.writer(out, lineterminator="\n").writerows(rows)
        self.record.write_text(out.getvalue(), encoding="utf-8")

    def document(self) -> dict:
        return json.loads(self.sbom.read_text(encoding="utf-8"))

    def write_sbom_keeping_record_true(self, document: dict) -> None:
        """Replace the SBOM and give it a correct RECORD line, so that the only
        disagreement left is whatever the caller put inside the document."""
        self.sbom.write_text(json.dumps(document), encoding="utf-8")
        data = self.sbom.read_bytes()
        rel = self.sbom.relative_to(self.site).as_posix()
        rows = [
            [rel, record_digest(data), str(len(data))] if row[0] == rel else row
            for row in csv.reader(io.StringIO(self.record.read_text("utf-8")))
            if row
        ]
        out = io.StringIO()
        csv.writer(out, lineterminator="\n").writerows(rows)
        self.record.write_text(out.getvalue(), encoding="utf-8")

    def snapshot(self) -> dict:
        return {
            path.relative_to(self.site).as_posix(): path.read_bytes()
            for path in sorted(self.site.rglob("*"))
            if path.is_file() and "__pycache__" not in path.parts
        }


class HardenVirtualenvSeedsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.script = load_script()

    def fixture(self, **kwargs) -> Fixture:
        fixture = Fixture(pathlib.Path(self.tmp.name), **kwargs)
        self.script.LIB_ROOT = fixture.lib
        self.script.DISTRO_WHEEL_DIR = fixture.distro
        return fixture

    def run_script(self) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), unittest.mock.patch(
            "sys.argv", ["harden-virtualenv-seeds.py"]
        ):
            self.script.main()
        return output.getvalue()

    def verify(self, fixture: Fixture) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.script.verify_consistency(fixture.embed, fixture.site)

    def test_keeps_only_the_highest_seed_wheel_of_each_project(self):
        fixture = self.fixture()
        self.run_script()
        self.assertEqual(
            sorted(p.name for p in fixture.embed.glob("*.whl")),
            ["pip-26.2.2-py3-none-any.whl", "setuptools-84.2.1-py3-none-any.whl"],
        )
        # The distribution's build was swapped in: its own file is there and
        # its patched urllib3 is what the seed wheel now vendors.
        members = wheel_members(fixture.embed / "pip-26.2.2-py3-none-any.whl")
        self.assertIn("pip/_vendor/urllib3/contrib/pyopenssl.py.orig", members)
        self.assertIn(b"urllib3==2.8.0", members["pip/_vendor/vendor.txt"])

    def test_every_record_hash_and_size_matches_the_file(self):
        fixture = self.fixture()
        self.run_script()
        rows = list(csv.reader(io.StringIO(fixture.record.read_text("utf-8"))))
        listed = {row[0] for row in rows}
        for path, digest, size in rows:
            if not digest:
                continue
            with self.subTest(path=path):
                target = fixture.site / path
                self.assertTrue(target.is_file(), f"RECORD names a missing file {path}")
                data = target.read_bytes()
                self.assertEqual(digest, record_digest(data))
                self.assertEqual(size, str(len(data)))
        for wheel in fixture.embed.glob("*.whl"):
            self.assertIn(f"{EMBED}/{wheel.name}", listed)
        self.assertNotIn(f"{EMBED}/pip-26.0.1-py3-none-any.whl", listed)
        self.assertNotIn(f"{EMBED}/setuptools-82.0.1-py3-none-any.whl", listed)

    def test_sbom_describes_the_wheels_on_disk(self):
        fixture = self.fixture()
        self.run_script()
        document = fixture.document()
        seeds = {c["name"]: c for c in document["components"]}
        self.assertEqual(sorted(seeds), ["pip", "setuptools"])

        for component in seeds.values():
            wheel = fixture.embed / (
                f"{component['name']}-{component['version']}-py3-none-any.whl"
            )
            data = wheel.read_bytes()
            with self.subTest(wheel=wheel.name):
                self.assertEqual(component["hashes"][0]["content"], sha256(data))
                evidence = component["evidence"]["identity"][0]["methods"][0]
                self.assertEqual(evidence["value"], sha256(data))
                with zipfile.ZipFile(wheel) as archive:
                    members = {
                        i.filename: archive.read(i)
                        for i in archive.infolist()
                        if not i.filename.endswith(".dist-info/RECORD")
                    }
                files = {
                    n["name"]: n for n in component["components"] if n["type"] == "file"
                }
                self.assertEqual(sorted(files), sorted(members))
                for name, content in members.items():
                    self.assertEqual(
                        files[name]["hashes"][0]["content"], sha256(content)
                    )
                    self.assertEqual(
                        {p["name"]: p["value"] for p in files[name]["properties"]}[
                            "size"
                        ],
                        str(len(content)),
                    )

        vendored = {
            n["name"]: n for n in seeds["pip"]["components"] if n["type"] == "library"
        }
        self.assertEqual(vendored["urllib3"]["version"], "2.8.0")
        self.assertEqual(vendored["urllib3"]["purl"], "pkg:pypi/urllib3@2.8.0")
        self.assertEqual(
            vendored["urllib3"]["bom-ref"],
            "pkg:pypi/pip@26.2.2#vendored/pkg:pypi/urllib3@2.8.0",
        )
        self.assertEqual(vendored["msgpack"]["version"], "1.2.1")
        self.assertEqual(vendored["certifi"]["version"], "2026.10.19")
        edges = {d["ref"]: d["dependsOn"] for d in document["dependencies"]}[
            "pkg:pypi/pip@26.2.2"
        ]
        self.assertIn("pkg:pypi/pip@26.2.2#vendored/pkg:pypi/urllib3@2.8.0", edges)
        self.assertNotIn("pkg:pypi/pip@26.2.2#vendored/pkg:pypi/urllib3@2.7.0", edges)

        inventory = json.dumps(
            {k: v for k, v in document.items() if k not in ("metadata", "formulation")}
        )
        for removed in ("pip@26.0.1", "setuptools@82.0.1", "urllib3@2.7.0"):
            self.assertNotIn(removed, inventory)

    def test_build_provenance_is_left_as_published(self):
        fixture = self.fixture()
        before = fixture.document()
        self.run_script()
        after = fixture.document()
        self.assertEqual(after["metadata"], before["metadata"])
        self.assertEqual(after["formulation"], before["formulation"])
        tool_versions = [
            t["version"]
            for t in after["metadata"]["tools"]["components"]
            if t["name"] == "setuptools"
        ]
        self.assertEqual(tool_versions, ["84.0.0"])

    def test_a_build_tool_at_a_removed_version_does_not_fail_the_build(self):
        # The upstream wheel could equally have been built with the setuptools
        # release that is removed here as superseded; naming it as a build tool
        # is a true statement about provenance, not stale inventory.
        fixture = self.fixture(tool_versions=("82.0.1",))
        before = fixture.document()["metadata"]
        self.run_script()
        self.assertEqual(fixture.document()["metadata"], before)

    def test_second_run_changes_nothing(self):
        fixture = self.fixture()
        self.run_script()
        first = fixture.snapshot()
        output = self.run_script()
        self.assertEqual(fixture.snapshot(), first)
        self.assertIn("nothing superseded", output)

    def test_self_check_rejects_a_stale_record_hash(self):
        fixture = self.fixture()
        self.run_script()
        rows = list(csv.reader(io.StringIO(fixture.record.read_text("utf-8"))))
        for row in rows:
            if row[0].endswith("sboms/virtualenv.cdx.json"):
                row[1] = record_digest(b"not the sbom")
        out = io.StringIO()
        csv.writer(out, lineterminator="\n").writerows(rows)
        fixture.record.write_text(out.getvalue(), encoding="utf-8")
        with self.assertRaises(SystemExit) as raised:
            self.verify(fixture)
        self.assertIn("RECORD hash or size", str(raised.exception))

    def test_self_check_rejects_a_stale_sbom_declaration(self):
        fixture = self.fixture()
        self.run_script()
        pristine = fixture.document()

        # The untampered document passes, so each failure below is caused by
        # the one field that case changes and not by the rewrite itself.
        fixture.write_sbom_keeping_record_true(pristine)
        self.verify(fixture)

        wheel = "pip-26.2.2-py3-none-any.whl"
        cases = {
            "wheel hash": (
                lambda pip: pip["hashes"][0].update(content="0" * 64),
                f"SHA-256 of {wheel} does not match",
            ),
            "file hash": (
                lambda pip: pip["components"][0]["hashes"][0].update(content="0" * 64),
                f"hash of {wheel}:",
            ),
            "vendored version": (
                lambda pip: next(
                    n for n in pip["components"] if n.get("name") == "urllib3"
                ).update(version="2.7.0"),
                "vendoring urllib3 2.7.0",
            ),
            "undeclared file": (
                lambda pip: pip["components"].pop(0),
                "which is not listed",
            ),
        }
        for label, (tamper, expected) in cases.items():
            with self.subTest(case=label):
                document = copy.deepcopy(pristine)
                tamper(next(c for c in document["components"] if c["name"] == "pip"))
                fixture.write_sbom_keeping_record_true(document)
                with self.assertRaises(SystemExit) as raised:
                    self.verify(fixture)
                self.assertIn(expected, str(raised.exception))

    def test_removal_policy_matches_the_installed_pip_hardening(self):
        pip_vendor = load_module(
            "harden_pip_vendor", SCRIPT.with_name("harden-pip-vendor.py")
        )
        self.assertEqual(self.script.REMOVED_VENDORED, pip_vendor.REMOVED_VENDORED)

    def test_seed_wheel_no_longer_vendors_what_the_installed_pip_drops(self):
        fixture = self.fixture()
        self.run_script()
        wheel = fixture.embed / "pip-26.2.2-py3-none-any.whl"
        members = wheel_members(wheel)
        self.assertFalse(
            [n for n in members if n.startswith("pip/_vendor/pkg_resources/")]
        )
        # The type stub stays, exactly as the installed hardening leaves it.
        self.assertIn("pip/_vendor/pkg_resources.pyi", members)
        self.assertNotIn(b"setuptools==", members["pip/_vendor/vendor.txt"])
        bom = json.loads(members["pip/_vendor/bom.cdx.json"])
        self.assertNotIn("setuptools", [c["name"] for c in bom["components"]])
        graph = json.dumps(bom["dependencies"])
        self.assertNotIn("setuptools", graph)

        # The wheel agrees with itself: its RECORD lists every member exactly.
        record = next(n for n in members if n.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(members[record].decode())))
        self.assertEqual(sorted(r[0] for r in rows), sorted(members))
        for path, digest, size in rows:
            if digest:
                self.assertEqual(digest, record_digest(members[path]), path)
                self.assertEqual(size, str(len(members[path])), path)

        # virtualenv's integrity record and SBOM describe the rewritten wheel.
        init = (fixture.embed / "__init__.py").read_text()
        self.assertIn(f'"{wheel.name}": "{sha256(wheel.read_bytes())}"', init)
        pip = next(c for c in fixture.document()["components"] if c["name"] == "pip")
        self.assertNotIn(
            "setuptools",
            [n["name"] for n in pip["components"] if n["type"] == "library"],
        )
        self.assertFalse(
            [n for n in pip["components"] if "pkg_resources/" in n.get("name", "")]
        )
        self.assertNotIn(
            "setuptools@70.3.0", json.dumps(fixture.document()["dependencies"])
        )

    def test_self_check_rejects_a_seed_wheel_that_vendors_a_removed_package(self):
        fixture = self.fixture()
        self.run_script()
        wheel = fixture.embed / "pip-26.2.2-py3-none-any.whl"
        members = wheel_members(wheel)
        members.pop(next(n for n in members if n.endswith(".dist-info/RECORD")))
        members["pip/_vendor/pkg_resources/__init__.py"] = b"# back again\n"
        make_wheel(wheel, "pip", "26.2.2", members)
        with self.assertRaises(SystemExit) as raised:
            self.verify(fixture)
        self.assertIn("still vendors pkg_resources", str(raised.exception))

    def test_a_swap_that_would_lower_a_vendored_package_is_refused(self):
        fixture = self.fixture(distro_certifi="2026.6.17")
        bundled = (fixture.embed / "pip-26.2.2-py3-none-any.whl").read_bytes()
        with self.assertRaises(SystemExit) as raised:
            self.run_script()
        self.assertIn("refusing to swap", str(raised.exception))
        self.assertIn("certifi 2026.10.19 -> 2026.6.17", str(raised.exception))
        self.assertEqual(
            (fixture.embed / "pip-26.2.2-py3-none-any.whl").read_bytes(), bundled
        )

    def test_a_swap_that_would_drop_a_vendored_package_is_refused(self):
        self.fixture(distro_without=("certifi",))
        with self.assertRaises(SystemExit) as raised:
            self.run_script()
        self.assertIn("certifi 2026.10.19 -> absent", str(raised.exception))

    def test_a_swap_is_kept_when_the_distro_wheel_already_dropped_pkg_resources(self):
        # A distro wheel that no longer vendors a REMOVED_VENDORED package has
        # lost nothing the build would keep, so the swap must still happen.
        fixture = self.fixture(distro_has_pkg_resources=False)
        self.run_script()
        members = wheel_members(fixture.embed / "pip-26.2.2-py3-none-any.whl")
        self.assertIn(b"urllib3==2.8.0", members["pip/_vendor/vendor.txt"])
        self.assertNotIn(b"setuptools==", members["pip/_vendor/vendor.txt"])
        self.verify(fixture)

    def test_self_check_rejects_a_seed_wheel_without_its_own_record(self):
        fixture = self.fixture()
        self.run_script()
        wheel = fixture.embed / "pip-26.2.2-py3-none-any.whl"
        members = wheel_members(wheel)
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, data in members.items():
                if not name.endswith(".dist-info/RECORD"):
                    archive.writestr(name, data)
        with self.assertRaises(SystemExit) as raised:
            self.verify(fixture)
        self.assertIn("has no RECORD", str(raised.exception))

    def run_distro_mode(self) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), unittest.mock.patch(
            "sys.argv", ["harden-virtualenv-seeds.py", "--distro-wheels"]
        ):
            self.script.main()
        return output.getvalue()

    def test_distro_wheels_mode_hardens_the_ensurepip_wheel(self):
        fixture = self.fixture()
        seeds_before = {w.name: w.read_bytes() for w in fixture.embed.glob("*.whl")}
        output = self.run_distro_mode()
        wheel = fixture.distro / "pip-26.2.2-py3-none-any.whl"
        members = wheel_members(wheel)
        self.assertFalse(
            [n for n in members if n.startswith("pip/_vendor/pkg_resources/")]
        )
        self.assertIn("pip/_vendor/pkg_resources.pyi", members)
        self.assertNotIn(b"setuptools==", members["pip/_vendor/vendor.txt"])
        record = next(n for n in members if n.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(members[record].decode())))
        self.assertEqual(sorted(r[0] for r in rows), sorted(members))
        for path, digest, size in rows:
            if digest:
                self.assertEqual(digest, record_digest(members[path]), path)
        self.assertIn("verified: every distro wheel", output)
        # Only the distro directory is touched in this mode.
        self.assertEqual(
            {w.name: w.read_bytes() for w in fixture.embed.glob("*.whl")}, seeds_before
        )
        # Idempotent: a second run leaves the wheel byte-identical.
        hardened = wheel.read_bytes()
        self.assertIn("no distro wheel vendors", self.run_distro_mode())
        self.assertEqual(wheel.read_bytes(), hardened)

    def test_full_build_order_leaves_seed_and_distro_wheels_consistent(self):
        # The Dockerfile order: seeds first (as nonroot), distro wheels last.
        fixture = self.fixture()
        self.run_script()
        self.run_distro_mode()
        self.verify(fixture)
        self.assertEqual(
            (fixture.embed / "pip-26.2.2-py3-none-any.whl").read_bytes(),
            (fixture.distro / "pip-26.2.2-py3-none-any.whl").read_bytes(),
        )

    def test_an_unknown_argument_is_refused(self):
        self.fixture()
        with self.assertRaises(SystemExit) as raised, unittest.mock.patch(
            "sys.argv", ["harden-virtualenv-seeds.py", "--distro"]
        ):
            self.script.main()
        self.assertIn("usage", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
