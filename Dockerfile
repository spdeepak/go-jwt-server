FROM golang:1.24 AS builder

ARG CGO_ENABLED
ARG GOOS
ARG GOARCH
ARG GO111MODULE
ARG GOPROXY
ARG GONOSUMDB
ARG TZ

WORKDIR /app

COPY Makefile go.mod go.sum ./

RUN go mod download
COPY . .
RUN make go-jwt-generate

RUN go build -a -v -o server ./cmd/server

FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080

ENTRYPOINT ["/app/server"]