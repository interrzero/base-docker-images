"""Tests for the file-level steps of scripts/harden-pip-vendor.py.

The fixture is a pip/_vendor tree shaped like pip 26.2.2's: a vendor.txt, a
bom.cdx.json declaring every vendored package with a dependency graph rooted
at pip, and the vendored pkg_resources package. The steps that import pip or
msgpack need a real installation and are exercised by the image build.

Run: python3 -m unittest discover -s tests/scripts -v
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[2] / "scripts" / "harden-pip-vendor.py"
)

PINS = {"msgpack": "1.2.1", "setuptools": "70.3.0", "urllib3": "2.8.0"}


def load_script():
    spec = importlib.util.spec_from_file_location("harden_pip_vendor", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HardenPipVendorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.script = load_script()
        self.vendor = pathlib.Path(self.tmp.name) / "_vendor"
        (self.vendor / "pkg_resources").mkdir(parents=True)
        (self.vendor / "pkg_resources" / "__init__.py").write_text("# vendored\n")
        (self.vendor / "pkg_resources.pyi").write_text("")
        (self.vendor / "vendor.txt").write_text(
            "".join(f"{name}=={version}\n" for name, version in PINS.items())
        )
        refs = {name: f"pkg:pypi/{name}@{version}" for name, version in PINS.items()}
        (self.vendor / "bom.cdx.json").write_text(
            json.dumps(
                {
                    "metadata": {"component": {"bom-ref": "bom-ref:pip"}},
                    "components": [
                        {"name": n, "version": v, "bom-ref": refs[n], "purl": refs[n]}
                        for n, v in PINS.items()
                    ],
                    "dependencies": [
                        {"ref": "bom-ref:pip", "dependsOn": list(refs.values())}
                    ]
                    + [{"ref": ref} for ref in refs.values()],
                }
            )
        )

    def harden_files(self) -> dict:
        self.script.remove_vendored_pkg_resources(self.vendor)
        self.script.rewrite_vendor_txt(self.vendor, "1.2.3")
        self.script.rewrite_bom(self.vendor, "1.2.3")
        return json.loads((self.vendor / "bom.cdx.json").read_text())

    def test_removed_package_leaves_no_trace_in_the_bom(self):
        bom = self.harden_files()
        self.assertNotIn("setuptools", [c["name"] for c in bom["components"]])
        # The dependency node and the edge from pip go with the component; left
        # behind they describe a package the image no longer contains.
        self.assertNotIn("setuptools", json.dumps(bom["dependencies"]))
        self.script.verify_bom_agrees(self.vendor)

    def test_policy_drives_the_directory_and_vendor_txt(self):
        self.harden_files()
        self.assertFalse((self.vendor / "pkg_resources").exists())
        self.assertTrue((self.vendor / "pkg_resources.pyi").exists())
        self.assertNotIn("setuptools", (self.vendor / "vendor.txt").read_text())
        self.assertIn("msgpack==1.2.3", (self.vendor / "vendor.txt").read_text())

    def test_bom_check_rejects_a_dependency_on_an_undeclared_component(self):
        self.harden_files()
        path = self.vendor / "bom.cdx.json"
        bom = json.loads(path.read_text())
        bom["dependencies"][0]["dependsOn"].append("pkg:pypi/setuptools@70.3.0")
        path.write_text(json.dumps(bom))
        with self.assertRaises(SystemExit) as raised:
            self.script.verify_bom_agrees(self.vendor)
        self.assertIn("no component declares", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
