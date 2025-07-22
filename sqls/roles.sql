-- name: ListRoles :many
SELECT *
FROM roles;

-- name: CreateNewRole :one
INSERT INTO roles (name, description, created_at, created_by, updated_at, updated_by)
VALUES (sqlc.arg('name'), sqlc.arg('description'), NOW(), sqlc.arg('createdBy'), NOW(), sqlc.arg('createdBy'))
RETURNING *;

-- name: GetRoleById :one
SELECT *
FROM roles
WHERE id = sqlc.arg('id');

-- name: UpdateRoleById :one
UPDATE roles
SET description = COALESCE(sqlc.narg('description'), description),
    name        = COALESCE(sqlc.narg('name'), name),
    updated_at  = NOW(),
    updated_by  = sqlc.arg('updated_by')
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: DeleteRoleById :exec
DELETE
FROM roles
WHERE id = sqlc.arg('id');