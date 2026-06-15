.PHONY: build test vet run
build:
	go build -o xpanel ./cmd/xpanel
test:
	go test ./...
vet:
	go vet ./...
run:
	go run ./cmd/xpanel
