# GitHub Actions Architecture

## Workflow Overview

| Workflow | Trigger | Purpose |
|---|---|---|
| **create-release-tag** | Push to main | Detects changed Dockerfiles, creates `release/*/vX.Y.Z` tags |
| **publish-base-images** | Release tag push or PR | Core pipeline: build, test, scan, push, sign, release, manifests |
| **daily-scan-and-rebuild** | Daily cron / manual | Scans GHCR images with Trivy, triggers rebuilds if upstream base updated |
| **manual-build-trigger** | GitHub UI dispatch | Manually trigger builds for specific or all images |
| **auto-approve-renovate** | Renovate PR opened | Auto-approves Renovate PRs using PAT_TOKEN |
| **auto-merge-renovate** | After publish/release completes, or GHA PR | Classifies update risk, enables GitHub auto-merge for safe updates |

## Flow Diagram

```
ENTRY POINTS (TRIGGERS)

  [Renovate Bot]        [Push to main]     [Release Tag]      [Daily Cron]     [Manual UI]
   opens/updates PR      Dockerfile change   release/**/v*      10:00 UTC        workflow_dispatch
       |                      |                  |                  |                |
       |                      |                  |                  |                |
       v                      v                  v                  v                v


FLOW 1: AUTOMATED TAGGING (on push to main)

  push to main
       |
       v
  +------------------------------------------+
  |  CREATE RELEASE TAG                       |
  |  create-release-tag.yml                   |
  |                                           |
  |  detect_changed_images                    |
  |  +- Checkout (fetch-depth: 0)             |
  |  +- Find all Dockerfile.* files           |
  |  +- Compare each to its latest tag        |
  |  +- Build JSON matrix of changed images   |
  |         |                                 |
  |         v (if has_changes)                |
  |  create_release_tags [matrix: image]      |
  |  +- Find latest tag per image             |
  |  +- Calculate next semver (patch bump)    |
  |  +- Create & push release/<name>/vX.Y.Z  |
  +---------------------+--------------------+
                        |
                        | pushes release tag
                        v

FLOW 2: BUILD & PUBLISH (on release tag push)

  release/**  tag pushed
       |
       v
  +------------------------------------------------------------------------+
  |  PUBLISH BASE DOCKER IMAGES                                             |
  |  publish-base-images.yml                                                |
  |                                                                         |
  |  +-------------------------------+                                      |
  |  | generate-matrix               |                                      |
  |  | +- Parse tag -> image name    |                                      |
  |  | +- Check deprecated images    |                                      |
  |  | +- Output: image-base-name,   |                                      |
  |  |    is_deprecated, tag          |                                      |
  |  +---------------+---------------+                                      |
  |                   | (if NOT deprecated)                                 |
  |                   v                                                     |
  |  +------------------------------------------------------+              |
  |  | publish_image [matrix: linux/amd64, linux/arm64]      |              |
  |  |                                                       |              |
  |  |  +- Parse image context (composite action)            |              |
  |  |  +- Check Dockerfile exists                           |              |
  |  |  +- Check Dockerfile changed since prev tag           |              |
  |  |  +- Check if image already published                  |              |
  |  |  +- Setup Docker (QEMU + Buildx + GHCR login)        |              |
  |  |  +- Extract metadata (tags, labels)                   |              |
  |  |  |                                                    |              |
  |  |  |  +--- BUILD --------------------------+            |              |
  |  |  +--| docker/build-push-action            |           |              |
  |  |  |  | load: true, push: false (local)     |           |              |
  |  |  |  +------------------------------------+            |              |
  |  |  |                                                    |              |
  |  |  |  +--- TEST ---------------------------+            |              |
  |  |  +--| Container structure tests           |           |              |
  |  |  |  +------------------------------------+            |              |
  |  |  |                                                    |              |
  |  |  |  +--- SCAN ---------------------------+            |              |
  |  |  +--| Trivy (CRITICAL,HIGH,MEDIUM)        |           |              |
  |  |  |  | exit-code: 1 (fail on vulns)        |           |              |
  |  |  |  +------------------------------------+            |              |
  |  |  |                                                    |              |
  |  |  |  +--- PUSH ---------------------------+            |              |
  |  |  +--| docker/build-push-action            |           |              |
  |  |  |  | push: true + provenance + SBOM      |           |              |
  |  |  |  +------------------------------------+            |              |
  |  |  |                                                    |              |
  |  |  |  +--- SIGN & ATTEST ------------------+            |              |
  |  |  +--| cosign sign (keyless/Sigstore)      |           |              |
  |  |  +--| actions/attest-build-provenance     |           |              |
  |  |  |  +------------------------------------+            |              |
  |  |  |                                                    |              |
  |  |  +- Extract language versions                         |              |
  |  |  +- Upload versions artifact                          |              |
  |  +----------------------------+-------------------------+              |
  |                               |                                        |
  |                               v                                        |
  |  +------------------------------------------+                          |
  |  | create_release                            |                          |
  |  | +- Download version artifacts             |                          |
  |  | +- Build release body (pull/verify docs)  |                          |
  |  | +- Create GitHub Release                  |                          |
  |  +---------------------+--------------------+                          |
  |                         |                                              |
  |                         v                                              |
  |  +------------------------------------------+                          |
  |  | create_multiarch_manifests                |                          |
  |  | +- Login to GHCR                          |                          |
  |  | +- Get platform-specific digests          |                          |
  |  | +- Create unified manifest (:version)     |                          |
  |  | +- Create unified manifest (:latest)      |                          |
  |  | +- Verify manifests                       |                          |
  |  +------------------------------------------+                          |
  +------------------------------------------------------------------------+
                        |
                        | workflow completes
                        v

FLOW 3: RENOVATE AUTO-MANAGEMENT

  Renovate Bot opens/syncs PR
       |
       +------------------------------------+
       v                                    v
  +-------------------------+   +--------------------------------------+
  | AUTO-APPROVE            |   | AUTO-MERGE                            |
  | auto-approve-           |   | auto-merge-renovate.yml               |
  | renovate.yml            |   |                                       |
  |                         |   | Triggers:                             |
  | pull_request_target     |   | +- pull_request_target (GHA PRs)      |
  | +- If actor is          |   | +- workflow_run (after Publish         |
  | |  renovate[bot]        |   |    or Create Release completes)       |
  | +- Approve PR via       |   |                                       |
  |    PAT_TOKEN            |   | +- Find associated Renovate PR        |
  +-------------------------+   | +- Classify update type:               |
                                | |  +- Digest -> auto-merge             |
                                | |  +- GH Actions -> auto-merge         |
                                | |  +- Docker minor/patch -> merge       |
                                | |  +- Major -> skip (manual review)     |
                                | +- Enable GitHub auto-merge (squash)    |
                                +----------------------------------------+


FLOW 4: DAILY VULNERABILITY SCAN & REBUILD

  Cron (daily 10:00 UTC) or manual dispatch
       |
       v
  +------------------------------------------------------------+
  |  VULNERABILITY SCAN AND REBUILD                             |
  |  daily-scan-and-rebuild.yml                                 |
  |                                                             |
  |  +- Discover all Dockerfile.* images                        |
  |  +- For each image, for each platform (amd64, arm64):       |
  |  |   +- Trivy scan GHCR :latest (CRITICAL,HIGH,MEDIUM)     |
  |  |                                                          |
  |  +- If vulns found:                                         |
  |  |   +- Check if upstream base image has newer digest       |
  |  |   +- If base updated -> add to rebuild list              |
  |  |   +- If base same -> skip (rebuild won't help)           |
  |  |                                                          |
  |  +- Also check: Dockerfile changed since last release?      |
  |  |                                                          |
  |  +- Cooldown check (24h default, 0h for CRITICAL)           |
  |  |                                                          |
  |  +- Create rebuild tags: release/<name>/vX.Y.Z+rebuild.TS  |
  |       |                                                     |
  +-------+-----------------------------------------------------+
          |
          | pushes release tag
          v
       (triggers FLOW 2: Publish Base Docker Images)


FLOW 5: MANUAL BUILD TRIGGER

  workflow_dispatch (GitHub UI)
  inputs: images, force_all, reason
       |
       v
  +--------------------------------------------------+
  |  MANUAL BUILD TRIGGER                             |
  |  manual-build-trigger.yml                         |
  |                                                   |
  |  trigger_builds                                   |
  |  +- If images specified -> use those              |
  |  +- If empty -> discover all Dockerfile.*         |
  |  +- For each image:                               |
  |  |   +- Find latest tag, bump patch version       |
  |  |   +- Create & push release/<name>/vX.Y.Z      |
  |  +- Print build summary                          |
  |       |                                           |
  +-------+-------------------------------------------+
          |
          | pushes release tag(s)
          v
       (triggers FLOW 2: Publish Base Docker Images)


COMPOSITE ACTIONS (shared helpers)

  .github/actions/
  +-- parse-image-context   -> Extracts image-name, version, platform-suffix from tag
  +-- setup-docker          -> QEMU + Buildx + GHCR login
  +-- extract-versions      -> Pulls language runtime versions from built image
  +-- scan-image            -> Reusable Trivy scan wrapper


END-TO-END HAPPY PATH

  Renovate PR -> Auto-Approve -> Merge to main -> Detect Changes -> Create Tag
       -> Build (amd64+arm64) -> Test -> Scan -> Push -> Sign -> Attest
       -> GitHub Release -> Multi-arch Manifest -> Auto-Merge Renovate PR

  Daily Scan -> Find Vulns + Outdated Base -> Rebuild Tag -> (same build pipeline)

  Manual Trigger -> Create Tag(s) -> (same build pipeline)
```

## Key Design Principle

Everything converges on release tags. Whether it's a code change, a daily scan, or a manual trigger, they all create `release/<image>/v*` tags which trigger the single `publish-base-images` pipeline that handles the full build-test-scan-sign-publish lifecycle.
