FROM golang:1.24 AS builder

LABEL maintainer="Deepak"
LABEL description="Aegis"
LABEL version="1.0.0"

ENV CGO_ENABLED=0
ENV GOOS=linux

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY Makefile ./
COPY . .
RUN make generate && go build -v -o server ./cmd/server

FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/server .
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080

ENTRYPOINT ["/app/server"]