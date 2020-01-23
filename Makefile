bin/snakeoil: cmd/snakeoil.go cmd/go.mod cmd/go.sum
	go build -trimpath -o $@ $<
