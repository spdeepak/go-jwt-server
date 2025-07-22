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

-- name: AssignPermissions :exec
INSERT INTO role_permissions (role_id, permission_id, created_at, created_by)
SELECT
    sqlc.arg('role_id'),
    unnest(sqlc.arg('permission_id')::uuid[]),
    now(),
    sqlc.arg('createdBy')
ON CONFLICT DO NOTHING;

-- name: RemovePermission :exec
DELETE
FROM role_permissions
WHERE role_id =$1
  AND permission_id = $2;