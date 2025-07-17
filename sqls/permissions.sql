-- name: ListPermissions :many
SELECT *
FROM permissions;

-- name: CreateNewPermission :one
INSERT INTO permissions (name, description, created_at, created_by, updated_at, updated_by)
VALUES (sqlc.arg('name'), sqlc.arg('description'), NOW(), sqlc.arg('createdBy'), NOW(), sqlc.arg('createdBy'))
RETURNING name, description, created_at, created_by;

-- name: GetPermissionById :one
SELECT *
FROM permissions
WHERE id = sqlc.arg('id');

-- name: UpdatePermissionById :exec
UPDATE permissions
SET description = COALESCE(sqlc.narg('description'), description),
    name        = COALESCE(sqlc.narg('name'), name),
    updated_at  = NOW(),
    updated_by  = sqlc.narg('updated_by')
WHERE id = sqlc.arg('id');

-- name: DeletePermissionById :exec
DELETE
FROM permissions
WHERE id = sqlc.arg('id');