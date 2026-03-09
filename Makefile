.PHONY: build api worker cli test lint clean docker-up docker-down

GO=go
BINARY_DIR=bin

build: api worker cli

api:
	$(GO) build -o $(BINARY_DIR)/api ./cmd/api

worker:
	$(GO) build -o $(BINARY_DIR)/worker ./cmd/worker

cli:
	$(GO) build -o $(BINARY_DIR)/cli ./cmd/cli

test:
	$(GO) test ./... -v -cover

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BINARY_DIR)

docker-up:
	docker-compose -f deployments/docker-compose.yml up -d

docker-down:
	docker-compose -f deployments/docker-compose.yml down

tidy:
	$(GO) mod tidy
