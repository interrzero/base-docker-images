test-current:
	docker build --no-cache --pull --progress=plain --tag python-base-current -f Dockerfile.current .
	trivy image --severity HIGH,CRITICAL,MEDIUM python-base-current
build-python:
	docker build --no-cache --pull --progress=plain --tag python-base-local -f Dockerfile.python-base .
build-python-fast:
	docker build --pull --progress=plain --tag python-base -f Dockerfile.python-base .
build-nodejs:
	docker build --no-cache --pull --progress=plain --tag nodejs-base-local -f Dockerfile.nodejs-base .
build-java:
	docker build --no-cache --pull --progress=plain --tag openjdk17-base-local -f openjdk17.nodejs-base .
run-docker:
	docker run -it --rm cdsp/python-base:latest
# run Docker image and print out PYTHON_ENV environment variable
run-docker-env: build-python-fast
	docker run --rm python-base:latest cat /tmp/versions.txt > versions.txt
run-local-action-tag:
	act push -e tag.json -W ./.github/workflows/publish-base-images.yml
run-local-action-push:
	act push -e main.json -W ./.github/workflows/create-release-tag.yml
trivy-python:
	docker build --pull --progress=plain --tag python-base -f Dockerfile.python-base .
	trivy image --severity HIGH,CRITICAL,MEDIUM python-base

# The version CI pins is read from the workflow rather than repeated here. Two
# hardcoded versions drift, and this copy drifting is the worse direction,
# because a local run that is quietly older keeps passing while CI fails.
ZIZMOR_PINNED := $(shell sed -n '/depName=zizmorcore\/zizmor/{n;s/.*version: *//p;}' \
	.github/workflows/workflow-security-scan.yml)

.PHONY: lint zizmor

# actionlint is not run by CI, so this is a local check rather than a preview of
# one. Note there is no -ignore for the action-reference format: this repository
# uses "./.github/actions/...", which actionlint accepts.
lint:
	SHELLCHECK_OPTS='--severity=warning' actionlint .github/workflows/*.yml

# Previews the findings the pinned CI gate reports, with the same persona,
# severity floor and inputs. --offline skips the audits that need the GitHub
# API; export GH_TOKEN and drop it to match CI exactly.
zizmor:
	@have=$$(zizmor --version | awk '{print $$2}'); \
	if [ "$$have" != "$(ZIZMOR_PINNED)" ]; then \
		echo "note: local zizmor $$have, CI pins $(ZIZMOR_PINNED) - findings may differ"; \
	fi
	zizmor --offline --persona=regular --min-severity=low \
		.github/workflows/ .github/actions/
