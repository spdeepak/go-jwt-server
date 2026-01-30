clean:
	find . -name "*.gen.go" -type f -delete

generate: clean
	#Create directory if it doesn't exist
	mkdir -p api
	# Generate API first boiler plate code
	go tool oapi-codegen -config .oapi-codegen.yaml openapi.yaml
	# Generate boiler plate repository layer code
	go tool sqlc generate
	# run other go:generate files for mocks
	go tool mockery
