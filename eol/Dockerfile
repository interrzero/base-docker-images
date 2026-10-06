# End-of-life marker image, pushed over a retired tag by hand.
#
# Deliberately not named Dockerfile.* at the repository root, so none of the
# build workflows discover it: this image is never part of a release.
#
# The result is a scratch image holding one static binary, installed as both
# /bin/sh and the entrypoint. It prints the baked-in message and exits 1, so a
# consumer's RUN steps and `docker run` both fail with the reason and the
# replacement image, instead of silently succeeding on an image that no longer
# receives security fixes. It has no OS packages, so it scans clean.
#
# The message is baked in at build time, so one binary serves every retired tag.

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:00fd4e9cdd9c5576c336d979fa663f9976f160c456b6ae9fe87e19c4e9c759a2 AS build

# hadolint ignore=DL3018
RUN apk add --no-cache build-base

COPY eol.c /src/eol.c
RUN gcc -static -Os -s -o /eol /src/eol.c

# RETIRED_REF is the retired image reference, REPLACEMENT_REF the image to use
# instead, PACKAGE_URL its package page, EOL_REASON one line of why.
ARG RETIRED_REF
ARG REPLACEMENT_REF
ARG ALTERNATIVE_REF
ARG PACKAGE_URL
ARG DOCS_URL
ARG EOL_REASON
RUN test -n "$RETIRED_REF" && test -n "$REPLACEMENT_REF" && test -n "$PACKAGE_URL" && \
    { \
      printf '\nERROR: %s has reached end of life and must not be used.\n\n' "$RETIRED_REF"; \
      printf '%s\n\n' "$EOL_REASON"; \
      printf 'Use this image instead:\n  %s\n' "$REPLACEMENT_REF"; \
      if [ -n "$ALTERNATIVE_REF" ]; then printf '  %s\n' "$ALTERNATIVE_REF"; fi; \
      printf '\nImage page:      %s\n' "$PACKAGE_URL"; \
      printf 'Migration notes: %s\n\n' "$DOCS_URL"; \
    } > /eol-message

FROM scratch
ARG RETIRED_REF
ARG REPLACEMENT_REF
COPY --from=build /eol /bin/sh
COPY --from=build /eol /eol
COPY --from=build /eol-message /etc/eol-message
# The marker label is what the retirement script verifies after pushing, and it
# has to be specific: org.opencontainers.image.deprecated is already set on
# real deprecated images in this repository, so it cannot distinguish a marker
# from an image that is merely on its way out.
LABEL io.interruptzero.base-docker-images.eol-marker="true" \
      org.opencontainers.image.deprecated="true" \
      org.opencontainers.image.vendor="InterruptZero.io" \
      org.opencontainers.image.title="End of life: ${RETIRED_REF}" \
      org.opencontainers.image.description="Retired. Use ${REPLACEMENT_REF} instead."
# Numeric, because scratch has no /etc/passwd. The binary and the message are
# world-readable, so nothing here needs root.
USER 65532:65532
ENTRYPOINT ["/eol"]
