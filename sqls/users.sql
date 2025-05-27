-- name: Signup :exec
INSERT INTO users (email, first_name, last_name, password, created_at, updated_at)
VALUES (sqlc.arg('email'), sqlc.arg('first_name'), sqlc.arg('last_name'), sqlc.arg('password'), NOW(), NOW());

-- name: UserLogin :one
SELECT *
FROM users
where email = sqlc.arg('email');

-- name: UpdateUser :exec
UPDATE users
SET first_name = COALESCE(sqlc.narg('first_name'), first_name),
    last_name  = COALESCE(sqlc.narg('last_name'), last_name),
    password   = COALESCE(sqlc.narg('password'), password),
    updated_at = NOW()
WHERE email = sqlc.arg('email');