"""Unit tests for the planning logic in ghcr-retention.py (no network)."""

import datetime as dt
import importlib.util
import pathlib
import sys

_spec = importlib.util.spec_from_file_location(
    "ghcr_retention", pathlib.Path(__file__).with_name("ghcr-retention.py"))
gr = importlib.util.module_from_spec(_spec)
# Registered before executing: dataclasses resolve annotations via sys.modules.
sys.modules[_spec.name] = gr
_spec.loader.exec_module(gr)

TODAY = dt.date(2026, 10, 26)


def d(n: int) -> str:
    return "sha256:" + f"{n:064x}"


def version(n: int, days_old: int, tags: list[str]) -> "gr.Version":
    return gr.Version(id=n, digest=d(n), created=TODAY - dt.timedelta(days=days_old), tags=tags)


def daily_releases(count: int, start_days_old: int = 100):
    """`count` releases one day apart, newest first, each an index with one child."""
    versions, children, releases = [], {}, {"python-3.13-base": set()}
    for i in range(count):
        tag = f"v1.1.{count - i}"
        releases["python-3.13-base"].add(tag.lstrip("v"))
        index, child = 1000 + i, 5000 + i
        versions.append(version(index, start_days_old + i, [tag]))
        versions.append(version(child, start_days_old + i, []))
        children[d(index)] = [d(child)]
    return versions, children, releases


def plan(versions, children, releases, package="python-3.13-base-linux-amd64", n=30, days=90):
    return gr.plan_package(package, versions, children, releases, TODAY, n, days)


def test_keeps_newest_n_when_all_are_old():
    versions, children, releases = daily_releases(35)
    p = plan(versions, children, releases)
    kept = [v for v in versions if v.tags and v.digest in p.keep]
    deleted = [v for v in versions if v.tags and v.digest in p.delete]
    assert len(kept) == 30 and len(deleted) == 5
    assert all(v.created < min(k.created for k in kept) for v in deleted)


def test_keeps_everything_younger_than_window_even_beyond_n():
    versions, children, releases = daily_releases(40, start_days_old=1)
    p = plan(versions, children, releases)
    assert not p.delete


def test_children_follow_their_index():
    versions, children, releases = daily_releases(35)
    p = plan(versions, children, releases)
    for index, kids in children.items():
        for kid in kids:
            assert (index in p.keep) == (kid in p.keep)
            assert (index in p.delete) == (kid in p.delete)


def test_child_shared_with_a_kept_index_is_never_deleted():
    versions, children, releases = daily_releases(35)
    oldest = versions[-2].digest                      # an index that will be deleted
    newest = versions[0].digest                       # an index that will be kept
    children[oldest] = children[oldest] + children[newest]
    p = plan(versions, children, releases)
    assert oldest in p.delete
    assert children[newest][0] in p.keep and children[newest][0] not in p.delete


def test_always_keep_tag_survives_an_out_of_window_release():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("latest")
    p = plan(versions, children, releases)
    assert versions[-2].digest in p.keep


def test_every_always_keep_entry_is_honoured():
    # Guards the list itself: adding an entry must protect it, so this test
    # does not go stale if ALWAYS_KEEP grows a frozen tag later.
    for tag in sorted(gr.ALWAYS_KEEP):
        versions, children, releases = daily_releases(35)
        versions[-2].tags.append(tag)
        p = plan(versions, children, releases)
        assert versions[-2].digest in p.keep, tag


def test_stale_tracking_tag_on_old_release_is_retired_and_release_deleted():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("v1.0")
    p = plan(versions, children, releases)
    assert p.retire == {"v1.0": versions[-2].digest}
    assert versions[-2].digest in p.delete


def test_moving_tracking_tag_on_new_release_is_not_retired():
    versions, children, releases = daily_releases(35)
    versions[0].tags += ["v1.1", "v1"]
    p = plan(versions, children, releases)
    assert not p.retire and versions[0].digest in p.keep


def test_semver_shaped_tag_without_a_git_release_is_not_a_release():
    releases = {"python-3.13-base": {"1.1.1"}}
    versions = [version(1, 200, ["1.29.3"])]
    p = plan(versions, {}, releases)
    assert d(1) in p.keep and d(1) in p.unknown and not p.delete


def test_legacy_release_without_v_prefix_is_a_release():
    releases = {"python-3.13-base": {"1.1.9"}}
    versions = [version(1, 400, ["1.1.9"])]
    p = plan(versions, {}, releases, n=0)
    assert d(1) in p.delete


def test_signatures_follow_their_subject():
    versions, children, releases = daily_releases(35)
    kept_hex = versions[0].digest.split(":")[1]
    gone_hex = versions[-2].digest.split(":")[1]
    versions.append(version(9001, 50, [f"sha256-{kept_hex}.sig"]))
    versions.append(version(9002, 200, [f"sha256-{gone_hex}.att"]))
    versions.append(version(9003, 200, [f"sha256-{gone_hex}"]))
    p = plan(versions, children, releases)
    assert d(9001) in p.keep
    assert d(9002) in p.delete and d(9003) in p.delete


def test_children_of_signature_indexes_follow_the_signature():
    # A referrers-tag index (sha256-<hex>) lists sigstore bundle manifests.
    versions, children, releases = daily_releases(35)
    kept_hex = versions[0].digest.split(":")[1]
    gone_hex = versions[-2].digest.split(":")[1]
    versions += [version(9101, 50, [f"sha256-{kept_hex}"]), version(9102, 50, []),
                 version(9201, 200, [f"sha256-{gone_hex}"]), version(9202, 200, [])]
    children[d(9101)] = [d(9102)]
    children[d(9201)] = [d(9202)]
    p = plan(versions, children, releases)
    assert d(9102) in p.keep and d(9102) not in p.orphans
    assert d(9202) in p.delete and d(9202) not in p.orphans


def test_unreferenced_untagged_version_is_reported_as_orphan_not_deleted():
    versions, children, releases = daily_releases(3, start_days_old=1)
    versions.append(version(7777, 300, []))
    p = plan(versions, children, releases)
    assert p.orphans == [d(7777)] and d(7777) not in p.delete


def test_orphans_split_into_superseded_indexes_and_unreferenced():
    versions, children, releases = daily_releases(3, start_days_old=1)
    versions += [version(8001, 5, []), version(8002, 300, [])]
    p = plan(versions, children, releases)
    kept_child = children[versions[0].digest][0]
    groups = gr.classify_orphans(p, {d(8001): [kept_child]})
    assert groups == {"superseded-index": [d(8001)], "unreferenced": [d(8002)]}


def test_sbom_suffix_counts_as_a_signature():
    assert gr.SIGNATURE.match("sha256-" + "a" * 64 + ".sbom")


def test_candidate_packages_cover_every_released_image_and_arch():
    got = gr.candidate_packages({"fips-140-3": {"1.1.1"}, "go-1.25-base": {"0.0.1"}})
    assert got == ["fips-140-3", "fips-140-3-linux-amd64", "fips-140-3-linux-arm64",
                   "go-1.25-base", "go-1.25-base-linux-amd64", "go-1.25-base-linux-arm64"]


def test_multi_arch_package_maps_to_its_image():
    assert gr.image_of("nodejs-24-base-linux-arm64") == "nodejs-24-base"
    assert gr.image_of("go-1.25-base") == "go-1.25-base"


def test_no_deletion_code_path_exists():
    """The safety claim of this script is that it cannot delete. Enforce it.

    Report-only is the whole basis on which this runs unattended against a
    registry, so it is asserted rather than left as an intention in a comment.
    If a deletion path is ever added deliberately, this test should be the
    thing that fails and forces the decision to be explicit.
    """
    import ast

    source = pathlib.Path(__file__).with_name("ghcr-retention.py").read_text()
    tree = ast.parse(source)

    # Checked structurally rather than by searching the text. The word itself
    # appears legitimately twice over: the module docstring promises "NOTHING
    # IS DELETED", and "delete" is a key in the report describing what a policy
    # WOULD remove. Matching raw text would fail on both and teach the reader
    # to ignore this test.
    #
    # urllib can only issue a DELETE via Request(method=...) or by overriding
    # get_method on a Request subclass, so those are the two things to forbid.
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert node.name != "get_method", "get_method override found"
        if isinstance(node, ast.keyword) and node.arg == "method":
            value = getattr(node.value, "value", None)
            assert str(value).upper() != "DELETE", "Request(method='DELETE') found"


def test_invariants_hold_on_a_realistic_plan():
    versions, children, releases = daily_releases(35)
    versions[-2].tags.append("latest")
    p = plan(versions, children, releases)
    assert gr.check_invariants(p, versions) == []


if __name__ == "__main__":
    # Runnable without pytest, so CI needs no extra dependency.
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    for name, fn in tests:
        fn()
        print(f"ok   {name}")
    print(f"{len(tests)} passed")
