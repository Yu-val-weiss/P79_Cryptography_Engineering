# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

RUN go install gotest.tools/gotestsum@latest
RUN env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o test2json -ldflags="-s -w" cmd/test2json

COPY . .

RUN go test -c ./...

# Minimal runtime stage
FROM alpine:latest

ENV GOVERSION=1.24

WORKDIR /app

COPY --from=builder /app/test2json /usr/local/bin/test2json
COPY --from=builder /go/bin/gotestsum /usr/local/bin/gotestsum
COPY --from=builder /app/*.test .

# Create an entry script to run all test binaries
RUN echo '#!/bin/sh' > run-tests.sh && \
    echo 'for test in *.test; do' >> run-tests.sh && \
    echo '  echo ""' >> run-tests.sh && \
    echo '  echo "=== Running tests for ${test%.test} ==="' >> run-tests.sh && \
    echo '  echo ""' >> run-tests.sh && \
    echo '  gotestsum --raw-command -- test2json -t -p ${test%.test} ./$test -test.v' >> run-tests.sh && \
    echo 'done' >> run-tests.sh && \
    chmod +x run-tests.sh


ENTRYPOINT [ "./run-tests.sh" ]