# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules
INPUT := $(word 2,$(MAKECMDGOALS))
INPUT2 := $(word 3,$(MAKECMDGOALS))

MODULES := mongodb redis sqlserver oracle
SDK_MODULE := github.com/openrundev/openrun/pkg/binding
# Set PUSH=1 to have `make release` push the commit and tags (used by the
# openrun repo's fullrelease target); default only creates them locally.
PUSH ?=

.DEFAULT_GOAL := help
ifeq ($(origin .RECIPEPREFIX), undefined)
  $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
endif
.RECIPEPREFIX = >

.PHONY: help test unit int lint release tags

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
>   (cd $$m && GOWORK=off golangci-lint run ./...)
> done

int: ## Run integration tests; optional arg: provider name, e.g. `make int redis` (default all)
> ./tests/run_int_tests.sh $(if $(INPUT),$(INPUT),all)

tags: ## Show the latest release tag of each provider
> @for m in $(MODULES); do
>   echo "$$m: $$(git tag -l "$$m/v*" --sort=-creatordate | head -n 1)"
> done

release: ## Tag a release (add PUSH=1 to also push); args: <sdk_version> <bindings_version>, e.g. `make release v0.2.0 v0.1.0`
> @if [[ -z "$(INPUT)" || -z "$(INPUT2)" ]]; then
>   echo "Usage: make release <sdk_version> <bindings_version>, e.g. make release v0.2.0 v0.1.0"
>   exit 1
> fi
> # Accept the openrun repo tag form (pkg/binding/vX.Y.Z) or the bare version
> sdk_version="$(INPUT)"
> sdk_version="$${sdk_version#pkg/binding/}"
> if [[ "$$sdk_version" != v* || "$(INPUT2)" != v* ]]; then
>   echo "Error: versions must start with v (got sdk '$$sdk_version', bindings '$(INPUT2)')"
>   exit 1
> fi
> if [[ -n "$$(git status --porcelain)" ]]; then
>   echo "Error: working tree is not clean, commit or stash changes first"
>   exit 1
> fi
> for m in $(MODULES); do
>   if git rev-parse -q --verify "refs/tags/$$m/$(INPUT2)" > /dev/null; then
>     echo "Error: tag $$m/$(INPUT2) already exists"
>     exit 1
>   fi
> done
> # Update every module to the requested SDK version; tidy fails the release
> # if the version is not published
> for m in $(MODULES); do
>   echo "--- $$m: pkg/binding $$sdk_version"
>   (cd $$m && go mod edit -require=$(SDK_MODULE)@$$sdk_version && GOWORK=off go mod tidy)
> done
> if [[ -n "$$(git status --porcelain)" ]]; then
>   git add $(foreach m,$(MODULES),$(m)/go.mod $(m)/go.sum)
>   git commit -m "Update pkg/binding to $$sdk_version for release $(INPUT2)"
> else
>   echo "go.mod files already at pkg/binding $$sdk_version"
> fi
> release_tags=""
> for m in $(MODULES); do
>   git tag -a "$$m/$(INPUT2)" -m "Release $$m/$(INPUT2)"
>   release_tags="$$release_tags $$m/$(INPUT2)"
> done
> if [[ "$(PUSH)" == "1" ]]; then
>   git push origin HEAD
>   # One push per tag: GitHub does not deliver push events (so the release
>   # workflow does not run) when more than three tags are pushed at once
>   for t in $$release_tags; do
>     git push origin "$$t"
>   done
>   echo "Pushed$$release_tags; the release workflow now builds and publishes each provider"
> else
>   echo "Created$$release_tags (not pushed); run: git push origin HEAD, then push each tag SEPARATELY"
>   echo "(one push per tag; GitHub skips push events when more than three tags are pushed at once):"
>   for t in $$release_tags; do
>     echo "  git push origin $$t"
>   done
>   echo "The release workflow then builds and publishes each provider"
> fi

# Swallow extra command line words used as arguments to targets (e.g. the
# version arguments of `make release`)
%:
> @:
