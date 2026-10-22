"""Tests for scripts/publish-failure-issue.sh.

The script runs as a job of the very publish run it reports on, so the run is
still in progress when it reads the logs. A stand-in for gh answers the calls
the script makes, and answers the way gh does for an unfinished run: "gh run
view --log-failed" fails with "run <id> is still in progress; logs will be
available when it is complete", while a finished job's own log is served.

The trivy table rows below use "|" where trivy draws box characters; the
script does not depend on either.

Run: python3 -m unittest discover -s tests/scripts -v
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[2] / "scripts" / "publish-failure-issue.sh"
)

GH_STUB = r'''#!/usr/bin/env python3
"""Stand-in for gh: answers the calls publish-failure-issue.sh makes."""
import json, os, pathlib, subprocess, sys

state = pathlib.Path(os.environ["GH_STUB_DIR"])
args = sys.argv[1:]
with open(state / "calls.log", "a") as log:
    log.write(json.dumps(args) + "\n")


def option(name):
    return args[args.index(name) + 1] if name in args else None


if args[:2] == ["run", "view"]:
    sys.stderr.write(
        "run %s is still in progress; logs will be available when it is complete\n"
        % args[2]
    )
    sys.exit(1)
if args[:2] == ["issue", "list"]:
    sys.exit(0)
if args[:2] in (["issue", "create"], ["issue", "edit"]):
    (state / "title").write_text(option("--title"))
    (state / "body").write_text(option("--body"))
    sys.exit(0)
if args[0] == "api":
    path = next(a for a in args[1:] if not a.startswith("-"))
    if path.endswith("/logs"):
        job = path.split("/")[-2]
        log = state / ("job-%s.log" % job)
        # job-<id>.fail holds how many more fetches of that log fail first.
        fail = state / ("job-%s.fail" % job)
        if fail.exists() and int(fail.read_text() or "0") > 0:
            fail.write_text(str(int(fail.read_text()) - 1))
            sys.stderr.write("HTTP 404: Not Found\n")
            sys.exit(1)
        if not log.exists():
            sys.stderr.write("HTTP 404: Not Found\n")
            sys.exit(1)
        sys.stdout.write(log.read_text())
        sys.exit(0)
    if "/jobs" in path:
        jobs = state / "jobs.json"
        if not jobs.exists():
            sys.stderr.write("HTTP 403: Resource not accessible by integration\n")
            sys.exit(1)
        result = subprocess.run(
            ["jq", "-r", option("--jq")],
            input=jobs.read_text(),
            capture_output=True,
            text=True,
            check=True,
        )
        sys.stdout.write(result.stdout)
        sys.exit(0)
sys.stderr.write("unexpected gh call: %r\n" % args)
sys.exit(2)
'''

# Job logs in the shape GitHub serves them: every line timestamped, each step
# opening with "##[group]Run" (an action's inner steps with "##[start-action"),
# run-block source echoed with a [36;1m escape, the runner's own closing
# "Process completed" error, and the post-job steps after "Post job cleanup.".
# CVE-2099-* strings sit in places that did not block the publish: a step that
# passed, the post-job steps, and a job that passed.
EARLIER_STEP = """\
2026-10-21T15:03:40.0000000Z ##[group]Run ./scripts/an-earlier-check.sh
2026-10-21T15:03:40.0100000Z [36;1m./scripts/an-earlier-check.sh[0m
2026-10-21T15:03:40.0200000Z ##[endgroup]
2026-10-21T15:03:40.1000000Z note: CVE-2099-0002 was reviewed and does not apply
"""

POST_JOB = """\
2026-10-21T15:04:53.0000000Z Post job cleanup.
2026-10-21T15:04:53.1000000Z ##[group]Generating build summary
2026-10-21T15:04:53.2000000Z cache note mentioning CVE-2099-0003
2026-10-21T15:04:53.3000000Z Artifact download URL: https://example.invalid/artifacts/1
"""

TRIVY_FAILURE = (
    EARLIER_STEP
    + """\
2026-10-21T15:04:46.0000000Z ##[start-action display=Run Trivy;id=__trivy-action.__run_4]
2026-10-21T15:04:46.0100000Z ##[group]Run entrypoint.sh
2026-10-21T15:04:46.0200000Z [36;1mentrypoint.sh[0m
2026-10-21T15:04:46.0300000Z ##[endgroup]
2026-10-21T15:04:52.8549928Z 2026-10-21T15:04:52Z\tINFO\t[wolfi] Detecting vulnerabilities...
2026-10-21T15:04:52.8607307Z Total: 1 (MEDIUM: 0, HIGH: 1, CRITICAL: 0)
2026-10-21T15:04:52.8610570Z | ca-certificates-bundle | CVE-2026-111943 | HIGH     | fixed  | 20260909-r2 | 20260909-r3 | golang: crypto/x509 |
2026-10-21T15:04:52.8652064Z ##[error]Process completed with exit code 1.
2026-10-21T15:04:52.8657921Z ##[end-action id=__trivy-action.__run_4;outcome=failure;conclusion=failure]
"""
    + POST_JOB
)

GATE_FAILURE = (
    EARLIER_STEP
    + """\
2026-10-21T15:04:03.3721108Z ##[group]Run ./scripts/check-virtualenv-seeds.sh "$IMAGE_REF" "$PLATFORM"
2026-10-21T15:04:03.3721623Z [36;1m./scripts/check-virtualenv-seeds.sh "$IMAGE_REF" "$PLATFORM"[0m
2026-10-21T15:04:03.3779485Z ##[endgroup]
2026-10-21T15:04:08.2668242Z   inventory references:
2026-10-21T15:04:08.2815979Z ##[error]inventory still declares setuptools versions that are not on disk:
2026-10-21T15:04:08.2825416Z       setuptools-84.0.0.dist-info
2026-10-21T15:04:08.2827839Z ##[error]Process completed with exit code 1.
"""
    + POST_JOB
)

# A job that passed is never read, even if its log mentions a CVE.
PASSING_JOB = "2026-10-21T15:01:00.0000000Z echo CVE-2099-0001 is only an example\n"


@unittest.skipUnless(shutil.which("jq") and shutil.which("bash"), "needs jq and bash")
class PublishFailureIssueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = pathlib.Path(self.tmp.name)
        bin_dir = self.state / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "gh"
        stub.write_text(GH_STUB)
        stub.chmod(0o755)
        self.env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("TAG_SHA", "MAIN_REF", "GITHUB_REPOSITORY", "GH_TOKEN")
        }
        self.env.update(
            PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            GH_REPO="example/base-images",
            GH_STUB_DIR=str(self.state),
            LOG_RETRY_DELAY_SECONDS="0",
        )

    def failed_run(self, failing_log: str) -> None:
        jobs = [
            {"id": 11, "name": "publish_image (linux/amd64)", "conclusion": "failure"},
            {"id": 12, "name": "publish_image (linux/arm64)", "conclusion": "failure"},
            {"id": 13, "name": "generate-matrix", "conclusion": "success"},
        ]
        (self.state / "jobs.json").write_text(json.dumps({"jobs": jobs}))
        (self.state / "job-11.log").write_text(failing_log)
        (self.state / "job-12.log").write_text(failing_log)
        (self.state / "job-13.log").write_text(PASSING_JOB)

    def open_issue(self, image: str = "nginx-base") -> tuple[str, str]:
        result = subprocess.run(
            ["bash", str(SCRIPT), "open", image, "https://example.invalid/run", "1001"],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return (self.state / "title").read_text(), (self.state / "body").read_text()

    def test_a_cve_failure_is_titled_with_its_findings(self):
        self.failed_run(TRIVY_FAILURE)
        title, body = self.open_issue()
        self.assertEqual(
            title, "nginx-base: publish blocked by 1 fixable MEDIUM+ finding(s)"
        )
        self.assertIn("CVE-2026-111943", body)
        # Only the failed step counts: not a passing job, not a passing step
        # of the failed job, not the post-job steps.
        for elsewhere in ("CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"):
            self.assertNotIn(elsewhere, body)
        calls = (self.state / "calls.log").read_text()
        self.assertNotIn('"view"', calls)
        self.assertIn('"--paginate"', calls)

    def test_a_gate_failure_without_cves_says_which_check_failed(self):
        self.failed_run(GATE_FAILURE)
        title, body = self.open_issue("python-3.14-base")
        self.assertEqual(
            title,
            "python-3.14-base: publish blocked by a failing gate check (no CVE findings)",
        )
        self.assertIn("inventory still declares setuptools versions", body)
        # The detail printed under the error line is carried with it.
        self.assertIn("setuptools-84.0.0.dist-info", body)
        for noise in (
            "Process completed with exit code",
            "Post job cleanup",
            "Artifact download URL",
            "36;1m",
            "CVE-2099",
        ):
            self.assertNotIn(noise, body)

    def test_a_job_log_not_served_at_first_is_retried(self):
        self.failed_run(TRIVY_FAILURE)
        (self.state / "job-11.fail").write_text("1")
        (self.state / "job-12.fail").write_text("2")
        title, body = self.open_issue()
        self.assertEqual(
            title, "nginx-base: publish blocked by 1 fixable MEDIUM+ finding(s)"
        )
        calls = (self.state / "calls.log").read_text()
        self.assertEqual(calls.count("/jobs/12/logs"), 3)

    def test_unreadable_logs_still_file_an_issue(self):
        title, body = self.open_issue()
        self.assertEqual(
            title,
            "nginx-base: publish blocked by a failing gate check (no CVE findings)",
        )
        self.assertIn("could not extract the finding table", body)


if __name__ == "__main__":
    unittest.main()
