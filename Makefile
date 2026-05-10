.PHONY: test

test:
	GOEXPERIMENT="jsonv2" go test -coverprofile=c.out ./...

html: test
	go tool cover -html=c.out -o ./coverage.html
