-- name: CreateDefaultSecret :exec
INSERT INTO jwt_secrets (secret)
VALUES (sqlc.arg('secret'));

-- name: GetDefaultSecret :one
SELECT *
FROM jwt_secrets
WHERE secret_type = 'default'
  AND is_valid = true;