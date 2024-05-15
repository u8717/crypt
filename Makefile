# Project configuration
GO_BUILD_FLAGS := -ldflags="-s -w" 

# Build targets
.PHONY: build clean help

build:  ## Builds the binary for the current system
	go build $(GO_BUILD_FLAGS) -o ./bin/crypt-tool ./cmd/crypt
	go build $(GO_BUILD_FLAGS) -o ./bin/keygen ./cmd/keygen

help: ## Shows this help message
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
