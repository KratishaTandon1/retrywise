SHELL := /bin/sh
.DEFAULT_GOAL := help

PYTHON ?= python3
PROJECT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
WORKSPACE_DIR := $(abspath $(PROJECT_DIR)/..)
ARTIFACT_DIR ?= $(PROJECT_DIR)/artifacts/evaluation
PYTHON_COMMAND := $(if $(findstring /,$(PYTHON)),$(abspath $(PYTHON)),$(PYTHON))

SMOKE_SEED ?= 42
SMOKE_CASES ?= 200
GOLDEN_SEED ?= 20260829
GOLDEN_CASES ?= 256
PRIMARY_CASES ?= 2000
FULL_CASES_PER_SEED ?= 2000
FULL_SEEDS ?= 101 211 307 401 503 601 701 809 907 1009
FULL_SEEDS_CSV ?= 101,211,307,401,503,601,701,809,907,1009

SOURCE_PATH = $(WORKSPACE_DIR):$(PROJECT_DIR)
RUN_PYTHON = cd "$(WORKSPACE_DIR)" && PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH="$(SOURCE_PATH)" "$(PYTHON_COMMAND)"
SIMULATOR = $(RUN_PYTHON) -m retrywise.packages.simulator
MULTI_SEED_SIMULATOR = $(RUN_PYTHON) -m retrywise.packages.simulator.multi_seed

.PHONY: help test unit api-test quality coverage package eval-smoke eval-primary eval-primary-verify eval-full eval-golden eval-smoke-determinism eval-golden-determinism eval-determinism ci

help:
	@printf '%s\n' \
	  'RetryWise development commands' \
	  '' \
	  '  make unit                         Run all dependency-free unittest suites' \
	  '  make api-test                     Require and run the FastAPI transport tests' \
	  '  make quality                      Run Ruff formatting/lint and Mypy' \
	  '  make coverage                     Enforce branch-aware coverage threshold' \
	  '  make package                      Build wheel and source distribution' \
	  '  make eval-smoke                   Run the 200-case seeded smoke evaluation' \
	  '  make eval-primary                 Run the frozen 2,000-case primary evaluation' \
	  '  make eval-primary-verify          Byte-compare primary evidence with current source' \
	  '  make eval-golden                  Run fixed adversarial cases with audit output' \
	  '  make eval-full                    Run 20,000 cases across ten fixed seeds' \
	  '  make eval-determinism             Prove smoke and golden JSON are byte-identical' \
	  '  make ci                           Run the local dependency-free CI contract'

test: unit

unit:
	@$(RUN_PYTHON) -m unittest discover -s retrywise/tests -v

api-test:
	@cd "$(PROJECT_DIR)" && RETRYWISE_REQUIRE_API_TESTS=1 "$(PYTHON_COMMAND)" -m unittest tests.control_plane.test_api tests.control_plane.test_openapi_contract -v

quality:
	@cd "$(PROJECT_DIR)" && "$(PYTHON_COMMAND)" -m ruff format --check packages services tests
	@cd "$(PROJECT_DIR)" && "$(PYTHON_COMMAND)" -m ruff check packages services tests
	@cd "$(PROJECT_DIR)" && "$(PYTHON_COMMAND)" -m mypy packages services

coverage:
	@cd "$(PROJECT_DIR)" && "$(PYTHON_COMMAND)" -m coverage erase
	@cd "$(PROJECT_DIR)" && "$(PYTHON_COMMAND)" -m coverage run -m unittest discover -s tests
	@cd "$(PROJECT_DIR)" && "$(PYTHON_COMMAND)" -m coverage report

package:
	@cd "$(PROJECT_DIR)" && "$(PYTHON_COMMAND)" -m build

eval-smoke:
	@$(SIMULATOR) \
	  --seed $(SMOKE_SEED) \
	  --cases $(SMOKE_CASES) \
	  --bootstrap-samples 100 \
	  --output "$(ARTIFACT_DIR)/smoke-seed-$(SMOKE_SEED).json"

eval-primary:
	@$(SIMULATOR) \
	  --seed $(SMOKE_SEED) \
	  --cases $(PRIMARY_CASES) \
	  --bootstrap-samples 400 \
	  --output "$(ARTIFACT_DIR)/primary-seed-$(SMOKE_SEED)-model-bound.json"

eval-primary-verify:
	@set -eu; \
	verification_file="$$(mktemp)"; \
	trap 'rm -f "$$verification_file"' EXIT HUP INT TERM; \
	$(SIMULATOR) \
	  --seed $(SMOKE_SEED) \
	  --cases $(PRIMARY_CASES) \
	  --bootstrap-samples 400 \
	  --output "$$verification_file"; \
	cmp -s "$(ARTIFACT_DIR)/primary-seed-$(SMOKE_SEED)-model-bound.json" "$$verification_file"; \
	printf '%s\n' 'Primary evidence is byte-identical to the current evaluation source.'

eval-golden:
	@$(SIMULATOR) \
	  --seed $(GOLDEN_SEED) \
	  --cases $(GOLDEN_CASES) \
	  --bootstrap-samples 200 \
	  --include-case-outcomes \
	  --output "$(ARTIFACT_DIR)/golden-seed-$(GOLDEN_SEED).json"

eval-full:
	@set -eu; \
	for seed in $(FULL_SEEDS); do \
	  cd "$(WORKSPACE_DIR)"; \
	  PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH="$(SOURCE_PATH)" "$(PYTHON_COMMAND)" \
	    -m retrywise.packages.simulator \
	    --seed "$$seed" \
	    --cases $(FULL_CASES_PER_SEED) \
	    --bootstrap-samples 400 \
	    --output "$(ARTIFACT_DIR)/full-seed-$$seed.json"; \
	done
	@$(MULTI_SEED_SIMULATOR) \
	  --seeds "$(FULL_SEEDS_CSV)" \
	  --cases $(FULL_CASES_PER_SEED) \
	  --bootstrap-samples 400 \
	  --output "$(ARTIFACT_DIR)/multi-seed-model-bound-20000.json"

eval-smoke-determinism:
	@$(SIMULATOR) \
	  --seed $(SMOKE_SEED) \
	  --cases $(SMOKE_CASES) \
	  --bootstrap-samples 100 \
	  --output "$(ARTIFACT_DIR)/smoke-determinism-a.json"
	@$(SIMULATOR) \
	  --seed $(SMOKE_SEED) \
	  --cases $(SMOKE_CASES) \
	  --bootstrap-samples 100 \
	  --output "$(ARTIFACT_DIR)/smoke-determinism-b.json"
	@cmp -s "$(ARTIFACT_DIR)/smoke-determinism-a.json" "$(ARTIFACT_DIR)/smoke-determinism-b.json"
	@printf '%s\n' 'Smoke replay is byte-for-byte deterministic.'

eval-golden-determinism:
	@$(SIMULATOR) \
	  --seed $(GOLDEN_SEED) \
	  --cases $(GOLDEN_CASES) \
	  --bootstrap-samples 200 \
	  --include-case-outcomes \
	  --output "$(ARTIFACT_DIR)/golden-determinism-a.json"
	@$(SIMULATOR) \
	  --seed $(GOLDEN_SEED) \
	  --cases $(GOLDEN_CASES) \
	  --bootstrap-samples 200 \
	  --include-case-outcomes \
	  --output "$(ARTIFACT_DIR)/golden-determinism-b.json"
	@cmp -s "$(ARTIFACT_DIR)/golden-determinism-a.json" "$(ARTIFACT_DIR)/golden-determinism-b.json"
	@printf '%s\n' 'Golden adversarial replay is byte-for-byte deterministic.'

eval-determinism: eval-smoke-determinism eval-golden-determinism

ci: unit eval-determinism
