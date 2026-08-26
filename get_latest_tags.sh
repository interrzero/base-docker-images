#!/bin/bash

# Function to increment patch version
increment_version() {
  local version=$1
  # Declared before assignment so a failing command substitution is not masked
  # by the "local" builtin's own exit status (SC2155).
  local ver_num major minor patch new_patch
  # Extract version number (remove release/image-name/v prefix)
  ver_num=$(echo "$version" | sed 's/.*\/v//')
  # Split into major.minor.patch
  major=$(echo "$ver_num" | cut -d. -f1)
  minor=$(echo "$ver_num" | cut -d. -f2)
  patch=$(echo "$ver_num" | cut -d. -f3)
  # Increment patch
  new_patch=$((patch + 1))
  echo "$major.$minor.$new_patch"
}

echo "Current latest tags and proposed new versions:"
echo "=============================================="

# Fetch latest tags from origin
git fetch origin --tags >/dev/null 2>&1

# Get latest tag for each image type and calculate new version.
# Images are discovered from the Dockerfiles present rather than hardcoded, so
# this cannot drift out of sync with the repo. The previous hardcoded list had
# already gone stale and omitted python-3.14-base.
for image in $(find . -maxdepth 1 -type f -name 'Dockerfile.*' ! -name 'deprecated.Dockerfile.*' -exec basename {} \; | sed 's/^Dockerfile\.//' | sort -u); do
  latest=$(git tag -l "release/$image/v*" | sort -V | tail -1)
  if [ -n "$latest" ]; then
    new_version=$(increment_version "$latest")
    new_tag="release/$image/v$new_version"
    echo "$image:"
    echo "  Current: $latest"
    echo "  New:     $new_tag"
    echo ""
  else
    echo "$image: No tags found"
    echo ""
  fi
done