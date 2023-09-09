GO ?= go

agentyesno: agentyesno.go
	go build -o $@

.PHONY: lint
lint:
	go vet ./...

.PHONY: clean
clean:
	rm -f agentyesno
