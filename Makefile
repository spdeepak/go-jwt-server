
go-jwt-generate:
	go tool oapi-codegen -generate gin,types,spec -package api ./openapi.yaml > api/openapi.gen.go