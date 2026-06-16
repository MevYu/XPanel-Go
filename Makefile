.PHONY: build build-full test test-full vet run
build:
	go build -o xpanel ./cmd/xpanel
build-full:
	go build -tags fleet -o xpanel ./cmd/xpanel
test:
	go test ./...
test-full:
	go test -tags fleet ./...
vet:
	go vet ./...
run:
	go run ./cmd/xpanel
