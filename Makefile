.PHONY: help lint test fmt init validate tflint clean all test-v0 test-v1 lint-v0 lint-v1 test-unit test-compliance

# Terraform parameters
TERRAFORM=terraform
TFLINT=tflint
TERRAFORM_COMPLIANCE=terraform-compliance
TEST_DIR=test

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format Terraform files
	@echo "Formatting v0..."
	@cd v0 && $(TERRAFORM) fmt -recursive
	@echo "Formatting v1..."
	@cd v1 && $(TERRAFORM) fmt -recursive

init: ## Initialize Terraform
	@echo "Initializing v0..."
	@cd v0 && $(TERRAFORM) init -backend=false
	@echo "Initializing v1..."
	@cd v1 && $(TERRAFORM) init -backend=false

validate: init ## Validate Terraform configuration
	@echo "Validating v0..."
	@cd v0 && $(TERRAFORM) validate
	@echo "Validating v1..."
	@cd v1 && $(TERRAFORM) validate

tflint: ## Run tflint
	@echo "Running tflint on v0..."
	@cd v0 && $(TFLINT) --init
	@cd v0 && $(TFLINT) --format compact
	@echo "Running tflint on v1..."
	@cd v1 && $(TFLINT) --init
	@cd v1 && $(TFLINT) --format compact

lint-v0: ## Run linting on v0 only
	@echo "Checking Terraform format for v0..."
	@cd v0 && $(TERRAFORM) fmt -check -recursive
	@echo "Running tflint on v0..."
	@cd v0 && $(TFLINT) --init
	@cd v0 && $(TFLINT) --format compact

lint-v1: ## Run linting on v1 only
	@echo "Checking Terraform format for v1..."
	@cd v1 && $(TERRAFORM) fmt -check -recursive
	@echo "Running tflint on v1..."
	@cd v1 && $(TFLINT) --init
	@cd v1 && $(TFLINT) --format compact

lint: ## Run all linting (fmt check + tflint) on both versions
	@echo "Checking Terraform format for v0..."
	@cd v0 && $(TERRAFORM) fmt -check -recursive
	@echo "Checking Terraform format for v1..."
	@cd v1 && $(TERRAFORM) fmt -check -recursive
	@$(MAKE) tflint

test-v0: ## Run Terraform validation for v0
	@echo "Initializing v0..."
	@cd v0 && $(TERRAFORM) init -backend=false
	@echo "Validating v0..."
	@cd v0 && $(TERRAFORM) validate
	@echo "v0 validation completed successfully"

test-v1: ## Run Terraform validation for v1
	@echo "Initializing v1..."
	@cd v1 && $(TERRAFORM) init -backend=false
	@echo "Validating v1..."
	@cd v1 && $(TERRAFORM) validate
	@echo "v1 validation completed successfully"

test: test-v0 test-v1 ## Run Terraform validation on both versions

test-unit: ## Run Terratest unit tests
	@echo "Running Terratest unit tests..."
	@cd $(TEST_DIR) && go test -v -timeout 10m

test-compliance-v0: ## Run terraform-compliance tests for v0
	@echo "Running terraform-compliance tests for v0..."
	@echo "Generating terraform plan for v0..."
	@cd v0 && $(TERRAFORM) plan -out=/tmp/tf-plan-v0.out || echo "Plan generation failed - skipping compliance"
	@if [ -f /tmp/tf-plan-v0.out ]; then \
		$(TERRAFORM_COMPLIANCE) -f ../compliance -p /tmp/tf-plan-v0.out; \
		rm -f /tmp/tf-plan-v0.out; \
	fi

test-compliance-v1: ## Run terraform-compliance tests for v1
	@echo "Running terraform-compliance tests for v1..."
	@echo "Generating terraform plan for v1..."
	@cd v1 && $(TERRAFORM) plan -out=/tmp/tf-plan-v1.out || echo "Plan generation failed - skipping compliance"
	@if [ -f /tmp/tf-plan-v1.out ]; then \
		$(TERRAFORM_COMPLIANCE) -f ../compliance -p /tmp/tf-plan-v1.out; \
		rm -f /tmp/tf-plan-v1.out; \
	fi

test-compliance: test-compliance-v0 test-compliance-v1 ## Run terraform-compliance tests on both versions

clean: ## Clean Terraform artifacts
	@echo "Cleaning v0..."
	@cd v0 && rm -rf .terraform .terraform.lock.hcl
	@echo "Cleaning v1..."
	@cd v1 && rm -rf .terraform .terraform.lock.hcl
	@cd $(TEST_DIR) && go clean -testcache

all: lint test test-unit ## Run linting, validation, and unit tests (default target)

.DEFAULT_GOAL := all
