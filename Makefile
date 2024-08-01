# Project configuration
GO_BUILD_FLAGS := -ldflags="-s -w" 

# Build targets
.PHONY: build clean help

build:  ## Builds the binary for the current system
	go build $(GO_BUILD_FLAGS) -o ./bin/cbccrypt ./cmd/cbccrypt
	go build $(GO_BUILD_FLAGS) -o ./bin/keygen ./cmd/keygen
	go build $(GO_BUILD_FLAGS) -o ./bin/files ./cmd/files

help: ## Shows this help message
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'