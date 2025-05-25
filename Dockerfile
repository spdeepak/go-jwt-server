FROM golang:1.24 AS builder

WORKDIR /app

#COPY --from=builder /app/application.yaml .
#COPY --from=builder /app/secrets.json .
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