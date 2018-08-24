bin/snakeoil: cmd/snakeoil.go cmd/go.mod cmd/go.sum
	docker run -v "$(PWD):/go/" -w "/go/cmd" -it golang:1.11rc2-stretch go install -ldflags="-s -w"
