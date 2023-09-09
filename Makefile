GO ?= go

agentyesno: agentyesno.go
	$(GO) build -o $@

.PHONY: lint
lint:
	$(GO) vet ./...

.PHONY: clean
clean:
	rm -f agentyesno
