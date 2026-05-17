.PHONY: build test lint clean

build:
	go build -o aguara-mcp .

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -f aguara-mcp mcp-aguara
