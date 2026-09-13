BUF := buf

.PHONY: proto proto-lint build test tidy

## Regenerate pb/ from proto/. The result is committed; CI fails if it drifts.
proto:
	$(BUF) generate

proto-lint:
	$(BUF) lint

build:
	go build ./...

test:
	go test ./...

tidy:
	go mod tidy
