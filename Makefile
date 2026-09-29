# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
INPUT := $(word 2,$(MAKECMDGOALS))
INPUT2 := $(word 3,$(MAKECMDGOALS))

MODULES := clickhouse databricks mongodb oracle snowflake sqlserver
SDK_MODULE := github.com/openrundev/openrun/pkg/binding
GOLANGCI_LINT_VERSION := v2.13.1
GOLANGCI_LINT = GOWORK=off go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
# PUSH=1 makes `make release` push the commit and tags (the openrun repo's
# fullrelease target sets it); by default they are only created locally.
PUSH ?=

.DEFAULT_GOAL := help
ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
endif
.RECIPEPREFIX = >

.PHONY: help test unit int lint modules release tags

help: ## Display this help section
> @awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: unit int ## Run all tests

# GOWORK=off: run in module mode so the local go.work (which replaces the
# pkg/binding SDK with a sibling openrun checkout for development) does not
# change what gets built/tested/linted; matches CI.
unit: ## Run unit tests for all provider modules
> for m in $(MODULES); do
>   echo "--- $$m"
>   (cd $$m && GOWORK=off go vet ./... && GOWORK=off go test ./...)
> done

lint: ## Run lint for all provider modules
> for m in $(MODULES); do
>   echo "--- $$m"
>   (cd $$m && $(GOLANGCI_LINT) run ./...)
> done

int: ## Run integration tests; optional arg: provider name, e.g. `make int mongodb` (default all)
> ./tests/run_int_tests.sh $(if $(INPUT),$(INPUT),all)

tags: ## Show the latest release tag of each provider
> @for m in $(MODULES); do
>   echo "$$m: $$(git tag -l "$$m/v*" --sort=-version:refname | head -n 1)"
> done

modules: ## Print provider module names for release orchestration
> @echo "$(MODULES)"

# ---------------------------------------------------------------------------
# Release
#
# Versions are given without the v prefix (e.g. 0.19.5); the tags add it.
# The SDK version must already be published as tag pkg/binding/v<sdk_version>
# in the openrun repo (`make release-sdk` or `make fullrelease` there): every
# provider module is pinned to it and tidied against the published module,
# which is what fails if the tag is missing.
#
#   make release <sdk_version> <bindings_version>         create the pin
#                                                          commit and tags
#   make release <sdk_version> <bindings_version> PUSH=1  also push them
#
# A pushed <provider>/v<version> tag triggers the release workflow, which
# builds and publishes that provider's binaries and OCI image.
# ---------------------------------------------------------------------------
release: ## Pin every provider to a pkg/binding SDK version and tag each provider; args: <sdk_version> <bindings_version>, add PUSH=1 to push
> @semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$$'
> sdk_version="$(INPUT)"
> sdk_version="$${sdk_version#pkg/binding/}"
> sdk_version="$${sdk_version#v}"
> version="$(INPUT2)"
> version="$${version#v}"
> for v in "$$sdk_version" "$$version"; do
>   if ! [[ "$$v" =~ $$semver_re ]]; then
>     echo "Usage: make release <sdk_version> <bindings_version> [PUSH=1], e.g. make release 0.19.5 0.19.5"
>     echo "Error: '$$v' is not a version like 0.19.5 or 0.19.5-rc.1"
>     exit 1
>   fi
> done
> # Everything is tagged from the current checkout: require a clean tree, and
> # when pushing, a main branch that is synchronized with origin/main
> if [[ -n "$$(git status --porcelain)" ]]; then
>   echo "Error: working tree has uncommitted changes, commit or stash them first"
>   exit 1
> fi
> if [[ "$(PUSH)" == "1" ]]; then
>   if [[ "$$(git branch --show-current)" != "main" ]]; then
>     echo "Error: a pushed release must run from main"
>     exit 1
>   fi
>   git fetch --quiet --prune --tags origin
>   if [[ "$$(git rev-parse HEAD)" != "$$(git rev-parse origin/main)" ]]; then
>     echo "Error: main is not synchronized with origin/main"
>     exit 1
>   fi
> fi
> for m in $(MODULES); do
>   if git rev-parse -q --verify "refs/tags/$$m/v$$version" > /dev/null; then
>     echo "Error: tag $$m/v$$version already exists"
>     exit 1
>   fi
> done
> # Pin every module to the SDK version; tidy fails if it is not published
> for m in $(MODULES); do
>   echo "--- $$m: pkg/binding v$$sdk_version"
>   (cd $$m && go mod edit -require=$(SDK_MODULE)@v$$sdk_version && GOWORK=off go mod tidy)
> done
> if [[ -n "$$(git status --porcelain)" ]]; then
>   git add $(foreach m,$(MODULES),$(m)/go.mod $(m)/go.sum)
>   git commit -q -m "Update pkg/binding to v$$sdk_version for release v$$version"
> else
>   echo "go.mod files already at pkg/binding v$$sdk_version"
> fi
> tags=""
> for m in $(MODULES); do
>   git tag -a "$$m/v$$version" -m "Release $$m/v$$version"
>   tags="$$tags $$m/v$$version"
> done
> if [[ "$(PUSH)" != "1" ]]; then
>   echo "Created$$tags (not pushed). To publish, push main and then each tag separately:"
>   echo "  git push origin HEAD"
>   for t in $$tags; do echo "  git push origin $$t"; done
>   exit 0
> fi
> git push origin HEAD:main
> # One push per tag: GitHub delivers no push events (so the release workflow
> # does not run) when more than three tags arrive in a single push
> for t in $$tags; do
>   git push origin "$$t"
> done
> echo "Pushed$$tags; the release workflow now builds and publishes each provider"

# Swallow extra command line words used as arguments to targets (e.g. the
# version arguments of `make release`)
%:
> @:
