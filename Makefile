.PHONY: test run stop integration-test

default: test

test:
	go test ./...

# Integration tests run against the docker-compose stack. Start the stack first with 'make run'.
integration-test:
	go test -tags=integration ./tests/

run:
	docker compose up -d --build

stop:
	docker compose down
