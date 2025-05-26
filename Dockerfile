FROM golang:1.24 AS builder

ENV CGO_ENABLED=0
ENV GOOS=linux

WORKDIR /app

COPY Makefile go.mod go.sum ./

RUN go mod download
COPY . .
RUN make go-jwt-generate

RUN go build -v -o server ./cmd/server

FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/server .
COPY --from=builder /app/migrations ./migrations
EXPOSE 8080

ENTRYPOINT ["/app/server"]