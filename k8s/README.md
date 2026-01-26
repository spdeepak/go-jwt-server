This is how to deploy thw image on your local k8s running on Mac.

1. Install `kind` and `kubectl`<br/>
    ```
    brew install kind kubectl
   ```
2. Create kind cluster if not already created<br/>
    ```
    kind create cluster
    kubectl get nodes
   ```
3. Build the Docker image with podman<br/>
    ```
    podman build -t aegis:dev .
   ```
4. Save and load image to kind cluster<br/>
    ```
   podman save localhost/aegis:dev -o aegis.tar
   kind load image-archive aegis.tar
   ```
5. Deploy PostgreSQL 18<br/>
    ```
   kubectl apply -f k8s/postgres.yaml
   ```
6. Wait for PostgreSQL to be ready<br/>
    ```
    kubectl wait --for=condition=ready pod -l app=postgres --timeout=60s
    kubectl get pods
   ```
7. Create data extension and run migrations<br/>
   ```
   kubectl exec deployment/postgres -- psql -U admin -d jwt_server -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"
   cat migrations/0001_initial.up.sql | kubectl exec -i deployment/postgres -- psql -U admin -d jwt_server
   ```
8. Apply application configuration
    ```
    Below command is to create configmap and save it to k8s/configmap.yaml
    kubectl create configmap aegis-config --from-file=configs/application.yaml --from-file=configs/secrets.json --dry-run=client -o yaml > k8s/configmap.yaml
    kubectl apply -f k8s/configmap.yaml
    kubectl apply -f k8s/deployment.yaml
    kubectl apply -f k8s/service.yaml
    ```
9. Wait for the application to be ready
    ```
    kubectl wait --for=condition=ready pod -l app=aegis --timeout=60s
    kubectl get pods
    ```
10. Check logs to verify it's running
    ```
    kubectl logs deployment/aegis
    ```
11. Access the service locally
    ```
    # Port forward to access the API
    kubectl port-forward svc/aegis 8080:80
    # In another terminal, test the API
    curl -X POST http://localhost:8080/api/v1/auth/signup \
      -H "Content-Type: application/json" \
      -d '{
        "email": "test@example.com",
        "firstName": "Test",
        "lastName": "User",
        "password": "TestPassword123!"
      }'
    ```

When building the image on arm-64 mac using podman it might fail. In that case increase the memory

* `podman machine stop` to stop the podman
* `podman machine set --memory 8192` to increase the memory to 8GB
* `podman machine set --cpus 4` to increase the cpus to 4
* `podman machine start` to start the podman
* `podman machine info` to see the info of the podman. Then Re-run the build