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
SELECT sqlc.arg('role_id'),
       unnest(sqlc.arg('permission_id')::uuid[]),
       now(),
       sqlc.arg('createdBy')
ON CONFLICT DO NOTHING;

-- name: UnAssignPermission :exec
DELETE
FROM role_permissions
WHERE role_id = $1
  AND permission_id = $2;

-- name: ListRolesAndItsPermissions :many
SELECT r.id          as role_id,
       r.name        as role_name,
       r.description as role_description,
       r.created_at  as role_created_at,
       r.created_by  as role_created_by,
       r.updated_at  as role_updated_at,
       r.updated_by  as role_updated_by,
       p.id          as permission_id,
       p.name        as permission_name,
       p.description as permission_description,
       p.created_at  as permission_created_at,
       p.created_by  as permission_created_by,
       p.updated_at  as permission_updated_at,
       p.updated_by  as permission_updated_by
FROM roles AS r
         LEFT JOIN role_permissions AS rp ON r.id = rp.role_id
         LEFT JOIN permissions AS p ON p.id = rp.permission_id
ORDER BY r.name, p.name;