
go-jwt-generate:
	go tool oapi-codegen -generate gin,types,spec -package api ./openapi.yaml > api/openapi.gen.go
	go tool sqlc generate
	@find . -type d -name repository | while read repo_dir; do \
		find "$$repo_dir" -maxdepth 1 -name '*.go' ! -name '*.gen.go' ! -name 'generate.go' -exec bash -c 'for f; do mv "$$f" "$${f%.go}.gen.go"; done' bash {} +; \
	done
	go generate ./...
