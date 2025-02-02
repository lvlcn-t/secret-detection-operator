.DEFAULT_GOAL := dev
SHELL := /bin/bash

.PHONY: dev
dev:
	@go run cmd/app/main.go

lint:
	@pre-commit run -a --hook-stage pre-commit
