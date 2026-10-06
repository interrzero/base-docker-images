#!/usr/bin/env bash
# Open, update or close the "publish blocked" issue for an image.
#
# A failed publish used to be visible only as a red run in the Actions tab.
# When python-3.13-base and python-3.14-base were rejected by their own gate on
# 2026-10-02, the published :latest silently stayed on the 2026-09-30 build for
# about nine hours while a downstream consumer's REQUIRED scan went red against
# it. Nothing told anyone: no issue, no message, and the daily job that
# dispatched the rebuild never checked whether the rebuild it asked for landed.
#
# One issue per image, reused rather than duplicated, closed automatically by
# the next successful publish of that image so the tracker reflects reality
# without anyone tidying it.
#
# Usage:
#   publish-failure-issue.sh open  <image> <run-url> [run-id]
#   publish-failure-issue.sh close <image> <run-url>
#
# Requires gh with issues:write. GH_TOKEN must be set by the caller.
set -euo pipefail

MODE="${1:?usage: publish-failure-issue.sh <open|close> <image> <run-url> [run-id]}"
IMAGE="${2:?missing image name}"
RUN_URL="${3:-}"
RUN_ID="${4:-}"
REPO="${GH_REPO:-${GITHUB_REPOSITORY:-}}"

[ -n "$REPO" ] || { echo "::error::GH_REPO or GITHUB_REPOSITORY must be set" >&2; exit 1; }

# Title carries a count that changes between runs, so the existing issue is
# found by its stable prefix rather than an exact match.
prefix="${IMAGE}: publish blocked"

# A re-run of an OLD tag cannot be made to pass: the workflow checks out the
# tag's tree, so it runs whatever guard scripts existed then, not the ones on
# main. Opening an issue for that misreports a healthy image as blocked - which
# happened: issue #468 claimed fips-base was blocked while its published image
# measured clean on both arches, because someone re-ran a tag predating the fix.
#
# If every gate script in the tag's tree is an ancestor state of main's - i.e.
# main has changed them since - the failure is explained by the tag being stale
# and is not evidence about the current image. Skipped only for "open"; closing
# is always safe.
# Compared against MAIN_REF, not HEAD: this job checks out the tag's tree, so
# HEAD *is* the tag and a self-comparison would always be empty.
if [ "$MODE" = open ] && [ -n "${TAG_SHA:-}" ] && [ -n "${MAIN_REF:-}" ] \
   && git rev-parse --verify --quiet "$MAIN_REF" >/dev/null 2>&1; then
  stale_guards=""
  for guard in $(git ls-tree -r --name-only "$MAIN_REF" -- scripts 2>/dev/null \
                 | grep -E '^scripts/(check-.*\.sh|harden-.*\.(py|js))$'); do
    if ! git diff --quiet "${TAG_SHA}" "${MAIN_REF}" -- "$guard" 2>/dev/null; then
      stale_guards="${stale_guards} ${guard}"
    fi
  done
  if [ -n "$stale_guards" ]; then
    echo "skipping issue for ${IMAGE}: the tag's gate scripts differ from ${MAIN_REF} (${stale_guards# })"
    echo "a re-run of a stale tag runs the old guards and cannot pass; this is not evidence about the published image"
    exit 0
  fi
fi

existing="$(gh issue list --repo "$REPO" --state open --limit 100 \
  --json number,title --jq "[.[] | select(.title | startswith(\"${prefix}\"))] | .[0].number // empty" 2>/dev/null || true)"

case "$MODE" in
  close)
    if [ -n "$existing" ]; then
      gh issue close "$existing" --repo "$REPO" \
        --comment "Resolved: ${IMAGE} published successfully. ${RUN_URL}" >/dev/null
      echo "closed issue #${existing} for ${IMAGE}"
    else
      echo "no open publish-blocked issue for ${IMAGE}; nothing to close"
    fi
    ;;
  open)
    findings=""
    if [ -n "$RUN_ID" ]; then
      # Pull the gate's own table out of the failed run rather than re-scanning,
      # so the issue shows exactly what blocked it. GitHub echoes run-block
      # source into the log prefixed with an escape sequence containing 36;1m;
      # filtering those out avoids quoting our own script back as if it were
      # scanner output.
      # Anchor on the ISO timestamp rather than a token count: the log prefix
      # is "(linux/arm64, ubuntu-24.04-arm)<TAB>UNKNOWN STEP<TAB><timestamp>",
      # and the space inside the parentheses breaks any field-count assumption.
      findings="$(gh run view "$RUN_ID" --repo "$REPO" --log-failed 2>/dev/null \
        | grep -vF '36;1m' \
        | grep -E 'CVE-[0-9]|GHSA-|Total: [0-9]' \
        | sed -E 's/^.*[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z //' \
        | grep -v '^[[:space:]]*#' \
        | sort -u | head -40 || true)"
    fi
    [ -n "$findings" ] || findings="(could not extract the finding table; see the run log)"

    # Only claim a CVE count when there are actually CVEs. A gate can fail for
    # reasons that are not findings at all - a guard that could not inspect the
    # image, a missing structure-test config - and titling those "blocked by 0
    # fixable MEDIUM+ findings" reads as nonsense and buries the real reason.
    # Observed for real: issue #468 said exactly that about a healthy image.
    count="$(printf '%s\n' "$findings" | grep -cE 'CVE-[0-9]|GHSA-' || true)"
    if [ "${count:-0}" -gt 0 ]; then
      title="${prefix} by ${count} fixable MEDIUM+ finding(s)"
    else
      title="${prefix} by a failing gate check (no CVE findings)"
    fi

    body="$(cat <<BODY
\`${IMAGE}\` failed its publish gate, so the published \`:latest\` is **stale**
and still serving the previous build. Consumers pulling it will keep seeing
whatever that build contains.

Run: ${RUN_URL}

### What the gate reported

\`\`\`
${findings}
\`\`\`

### What to do

Fix the finding at source in the image, not with an ignore entry - a
suppression never reaches downstream consumers, who scan with their own tools.
This issue closes automatically on the next successful publish of
\`${IMAGE}\`.
BODY
)"

    if [ -n "$existing" ]; then
      gh issue edit "$existing" --repo "$REPO" --title "$title" --body "$body" >/dev/null
      echo "updated issue #${existing} for ${IMAGE}"
    else
      gh issue create --repo "$REPO" --title "$title" --body "$body" >/dev/null
      echo "opened a publish-blocked issue for ${IMAGE}"
    fi
    ;;
  *)
    echo "::error::unknown mode '${MODE}' (expected open or close)" >&2
    exit 2
    ;;
esac
