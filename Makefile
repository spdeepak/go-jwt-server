
go-jwt-generate:
	#Create directory if it doesn't exist
	mkdir -p api
	# Generate API first boiler plate code
	go tool oapi-codegen -generate gin,types,spec -package api ./openapi.yaml > api/openapi.gen.go
	# Generate boiler plate repository layer code
	go tool sqlc generate
	# rename repository layer code filenames
	@find . -type d -name repository | while read repo_dir; do \
		find "$$repo_dir" -maxdepth 1 -name '*.go' ! -name '*.gen.go' ! -name 'generate.go' -exec bash -c 'for f; do mv "$$f" "$${f%.go}.gen.go"; done' bash {} +; \
	done
	# run other go:generate files for mocks
	go generate ./...
