#!/bin/bash

# trigger_builds.sh - Automated script to trigger Docker image builds
# 
# This script creates release tags for Docker images that have been modified
# since their last tag, triggering GitHub Actions workflows to build and publish.

set -e

# Function to increment patch version
increment_version() {
  local version=$1
  local ver_num=$(echo "$version" | sed 's/.*\/v//')
  local major=$(echo "$ver_num" | cut -d. -f1)
  local minor=$(echo "$ver_num" | cut -d. -f2)
  local patch=$(echo "$ver_num" | cut -d. -f3)
  local new_patch=$((patch + 1))
  echo "$major.$minor.$new_patch"
}

# Function to get the latest tag for an image
get_latest_tag() {
  local image=$1
  git tag -l "release/$image/v*" | sort -V | tail -1
}

# Function to check if Dockerfile was modified since last tag
dockerfile_modified_since_tag() {
  local image=$1
  local dockerfile="Dockerfile.$image"
  local latest_tag=$(get_latest_tag "$image")
  
  if [ -z "$latest_tag" ]; then
    echo "INFO: No previous tag found for $image, assuming modified"
    return 0
  fi
  
  if git diff --name-only "$latest_tag" HEAD | grep -q "^$dockerfile$"; then
    return 0  # Modified
  else
    return 1  # Not modified
  fi
}

# Usage function
usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --force-all       Force build all images regardless of changes"
  echo "  --image IMAGE     Build specific image only"
  echo "  --dry-run         Show what would be done without making changes"
  echo "  --help           Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0                          # Build only modified images"
  echo "  $0 --force-all              # Force build all images"
  echo "  $0 --image python-base      # Build only python-base"
  echo "  $0 --dry-run                # Show what would be built"
}

# Parse command line arguments
FORCE_ALL=false
DRY_RUN=false
SPECIFIC_IMAGE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --force-all)
      FORCE_ALL=true
      shift
      ;;
    --image)
      SPECIFIC_IMAGE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

# Main function
main() {
  echo "i0-images Automated Build Trigger"
  echo "======================================"
  
  # Ensure we're on main branch
  current_branch=$(git branch --show-current)
  if [ "$current_branch" != "main" ]; then
    echo "ERROR: Must be on main branch. Current: $current_branch"
    exit 1
  fi
  
  # Ensure working directory is clean (unless dry run)
  if [ "$DRY_RUN" = false ] && ! git diff --quiet; then
    echo "ERROR: Working directory must be clean. Please commit or stash changes."
    exit 1
  fi
  
  # Fetch latest tags
  echo "INFO: Fetching latest tags from origin..."
  git fetch origin --tags >/dev/null 2>&1
  
  # List all available images
  images=(fips-base go-1.25-base nginx-base nodejs-24-base python-3.13-base wolfi-base openjdk-17-base)
  modified_images=()
  
  echo "INFO: Checking for modified Dockerfiles..."
  
  # Determine which images to build
  if [ "$FORCE_ALL" = true ]; then
    echo "INFO: Force build mode enabled - all images will be built"
    modified_images=("${images[@]}")
  elif [ -n "$SPECIFIC_IMAGE" ]; then
    echo "INFO: Building specific image: $SPECIFIC_IMAGE"
    # Validate image name
    if [[ " ${images[@]} " =~ " ${SPECIFIC_IMAGE} " ]]; then
      modified_images=("$SPECIFIC_IMAGE")
    else
      echo "ERROR: Unknown image: $SPECIFIC_IMAGE"
      echo "Available images: ${images[*]}"
      exit 1
    fi
  else
    # Check each image for modifications
    for image in "${images[@]}"; do
      if dockerfile_modified_since_tag "$image"; then
        modified_images+=("$image")
        latest_tag=$(get_latest_tag "$image")
        if [ -n "$latest_tag" ]; then
          echo "MODIFIED: $image (changed since $latest_tag)"
        else
          echo "MODIFIED: $image (no previous tags found)"
        fi
      else
        echo "UNCHANGED: $image (no changes since last tag)"
      fi
    done
  fi
  
  if [ ${#modified_images[@]} -eq 0 ]; then
    echo "INFO: No modified Dockerfiles found. No builds needed."
    exit 0
  fi
  
  echo ""
  echo "INFO: Images to build: ${modified_images[*]}"
  
  if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "DRY RUN: Would create the following tags:"
    for image in "${modified_images[@]}"; do
      latest_tag=$(get_latest_tag "$image")
      if [ -n "$latest_tag" ]; then
        new_version=$(increment_version "$latest_tag")
      else
        new_version="1.0.0"
      fi
      new_tag="release/$image/v$new_version"
      echo "  - $new_tag"
    done
    echo ""
    echo "DRY RUN: Would push ${#modified_images[@]} tags individually"
    exit 0
  fi
  
  # Create and push tags
  echo ""
  echo "INFO: Creating release tags..."
  
  for image in "${modified_images[@]}"; do
    latest_tag=$(get_latest_tag "$image")
    if [ -n "$latest_tag" ]; then
      new_version=$(increment_version "$latest_tag")
    else
      new_version="1.0.0"
    fi
    
    new_tag="release/$image/v$new_version"
    commit_msg="Release $image v$new_version with InterruptZero.io branding"
    
    echo "INFO: Creating tag: $new_tag"
    git tag -a "$new_tag" -m "$commit_msg"
    
    echo "INFO: Pushing tag: $new_tag"
    if git push origin "$new_tag"; then
      echo "SUCCESS: Pushed $new_tag - GitHub Actions workflow triggered"
    else
      echo "ERROR: Failed to push $new_tag"
      exit 1
    fi
  done
  
  echo ""
  echo "SUCCESS: Build trigger completed!"
  echo "Summary:"
  echo "  - Modified images: ${#modified_images[@]}"
  echo "  - Tags created and pushed: ${#modified_images[@]}"
  echo ""
  echo "Monitor workflow progress at:"
  echo "  https://github.com/interrzero/base-docker-images/actions"
}

# Run main function
main