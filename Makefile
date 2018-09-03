bin/snakeoil: cmd/snakeoil.go cmd/go.mod cmd/go.sum
	docker run -v "$(PWD):/go/" -w "/go/cmd" -it golang:1.11-stretch go install -ldflags="-s -w"

bin/snakeoil-linux-amd64: bin/snakeoil
	cp bin/snakeoil bin/snakeoil-linux-amd64
