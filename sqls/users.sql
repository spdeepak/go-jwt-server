-- name: Signup :exec
INSERT INTO users (email, first_name, last_name, password, two_fa_enabled, created_at, updated_at)
VALUES (sqlc.arg('email'), sqlc.arg('first_name'), sqlc.arg('last_name'), sqlc.arg('password'),
        sqlc.arg('two_fa_enabled'), NOW(), NOW());

-- name: SignupWith2FA :exec
WITH signup_new_user AS (
    INSERT INTO users (email, first_name, last_name, password, two_fa_enabled, created_at, updated_at)
        VALUES (sqlc.arg('email'), sqlc.arg('first_name'), sqlc.arg('last_name'), sqlc.arg('password'),
                sqlc.arg('two_fa_enabled'), NOW(), NOW())
        RETURNING id)
INSERT
INTO users_2fa (user_id, secret, url, created_at)
SELECT id, sqlc.arg('secret'), sqlc.arg('url'), NOW()
FROM signup_new_user;

-- name: GetUserByEmail :one
SELECT *
FROM users
where email = sqlc.arg('email');

-- name: GetUserById :one
SELECT *
FROM users
where id = sqlc.arg('id');

-- name: Setup2FA :exec
WITH revoke_old_2fa AS (
    UPDATE users_2fa
        SET revoked = true
        WHERE users_2fa.user_id = sqlc.arg('revoke_user_id')),
     setup_new_2fa AS (
         INSERT
             INTO users_2fa (user_id, secret, url, created_at)
                 VALUES (sqlc.arg('user_id'), sqlc.arg('secret'), sqlc.arg('url'), now()))
UPDATE users
SET two_fa_enabled = true
WHERE users.id = sqlc.arg('user_id');

-- name: GetEntireUserByEmail :one
WITH user_base AS (SELECT *
                   FROM users
                   WHERE email = sqlc.arg('email')),
-- User → Roles
     user_roles_joined AS (SELECT r.name AS role_name, ur.user_id
                           FROM user_base u
                                    LEFT JOIN user_roles ur ON ur.user_id = u.id
                                    LEFT JOIN roles r ON r.id = ur.role_id),
-- Permissions directly assigned to user
     user_permissions_direct AS (SELECT p.name AS permission_name, up.user_id
                                 FROM user_base u
                                          LEFT JOIN user_permissions up ON up.user_id = u.id
                                          LEFT JOIN permissions p ON p.id = up.permission_id),
-- Permissions inherited via roles
     user_permissions_via_roles AS (SELECT p.name AS permission_name, ur.user_id
                                    FROM user_base u
                                             JOIN user_roles ur ON ur.user_id = u.id
                                             JOIN role_permissions rp ON rp.role_id = ur.role_id
                                             JOIN permissions p ON p.id = rp.permission_id),
-- Union all permissions (direct + role-based)
     all_user_permissions AS (SELECT permission_name, user_id
                              FROM user_permissions_direct
                              UNION
                              SELECT permission_name, user_id
                              FROM user_permissions_via_roles)

SELECT u.id         AS user_id,
       u.email,
       u.password,
       u.first_name,
       u.last_name,
       u.locked,
       u.two_fa_enabled,
       u.disabled,
       u.created_at AS user_created_at,

       COALESCE(
                       ARRAY_AGG(DISTINCT r.role_name)
                       FILTER (WHERE r.role_name IS NOT NULL),
                       '{}'
       )::text[]    AS role_names,

       COALESCE(
                       ARRAY_AGG(DISTINCT p.permission_name)
                       FILTER (WHERE p.permission_name IS NOT NULL),
                       '{}'
       )::text[]    AS permission_names

FROM user_base u
         LEFT JOIN user_roles_joined r ON r.user_id = u.id
         LEFT JOIN all_user_permissions p ON p.user_id = u.id
GROUP BY u.id, u.email, u.password,
         u.first_name, u.last_name,
         u.locked, u.disabled, u.two_fa_enabled,
         u.created_at;

-- name: GetUserRolesAndPermissionsFromID :one
WITH user_base AS (SELECT *
                   FROM users
                   WHERE users.id = sqlc.arg('id')),
-- User → Roles
     user_roles_joined AS (SELECT r.name AS role_name, ur.user_id
                           FROM user_base u
                                    LEFT JOIN user_roles ur ON ur.user_id = u.id
                                    LEFT JOIN roles r ON r.id = ur.role_id),
-- Permissions directly assigned to user
     user_permissions_direct AS (SELECT p.name AS permission_name, up.user_id
                                 FROM user_base u
                                          LEFT JOIN user_permissions up ON up.user_id = u.id
                                          LEFT JOIN permissions p ON p.id = up.permission_id),
-- Permissions inherited via roles
     user_permissions_via_roles AS (SELECT p.name AS permission_name, ur.user_id
                                    FROM user_base u
                                             JOIN user_roles ur ON ur.user_id = u.id
                                             JOIN role_permissions rp ON rp.role_id = ur.role_id
                                             JOIN permissions p ON p.id = rp.permission_id),
-- Union all permissions (direct + role-based)
     all_user_permissions AS (SELECT permission_name, user_id
                              FROM user_permissions_direct
                              UNION
                              SELECT permission_name, user_id
                              FROM user_permissions_via_roles)

SELECT u.id                                                                                                       AS user_id,
       u.email,
       u.first_name,
       u.last_name,
       u.locked,
       u.two_fa_enabled,
       u.created_at                                                                                               AS user_created_at,
       COALESCE(ARRAY_AGG(DISTINCT r.role_name) FILTER (WHERE r.role_name IS NOT NULL),
                '{}')::text[]                                                                                     AS role_names,
       COALESCE(ARRAY_AGG(DISTINCT p.permission_name) FILTER (WHERE p.permission_name IS NOT NULL),
                '{}')::text[]                                                                                     AS permission_names
FROM user_base u
         LEFT JOIN user_roles_joined r ON r.user_id = u.id
         LEFT JOIN all_user_permissions p ON p.user_id = u.id
GROUP BY u.id, u.email, u.password,
         u.first_name, u.last_name,
         u.locked, u.two_fa_enabled,
         u.created_at;

-- name: AssignRolesToUser :exec
INSERT INTO user_roles (user_id, role_id, created_at, created_by)
SELECT sqlc.arg('user_id'),
       unnest(sqlc.arg('role_id')::uuid[]),
       now(),
       sqlc.arg('createdBy')
ON CONFLICT DO NOTHING;

-- name: AssignPermissionToUser :exec
INSERT INTO user_permissions (user_id, permission_id, created_at, created_by)
SELECT sqlc.arg('user_id'),
       unnest(sqlc.arg('permission_id')::uuid[]),
       now(),
       sqlc.arg('createdBy')
ON CONFLICT DO NOTHING;

-- name: UnassignRolesToUser :exec
DELETE
FROM user_roles
where user_id = sqlc.arg('user_id')
  and role_id = sqlc.arg('role_id');

-- name: UnassignPermissionToUser :exec
DELETE
FROM user_permissions
where user_id = sqlc.arg('user_id')
  and permission_id = sqlc.arg('permission_id');

-- name: SearchAndGetUserDetails :one
WITH user_base AS (SELECT *
                   FROM users
                   WHERE (sqlc.narg('email') IS NULL OR users.email = sqlc.narg('email'))
                      OR (sqlc.narg('first_name') IS NULL OR
                          users.first_name ILIKE '%' || sqlc.narg('first_name') || '%')
                      OR (sqlc.narg('last_name') IS NOT NULL AND sqlc.narg('last_name') <> '' AND
                          users.last_name ILIKE '%' || sqlc.narg('last_name') || '%')),
     user_roles_joined AS (SELECT r.id          AS id,
                                  r.name        AS name,
                                  r.description AS description,
                                  ur.user_id    AS user_id,
                                  ur.created_at AS since
                           FROM user_base u
                                    LEFT JOIN user_roles ur ON ur.user_id = u.id
                                    LEFT JOIN roles r ON ur.role_id = r.id),
     user_permissions_joined AS (SELECT p.name         AS permission_name,
                                        p.description AS description,
                                        up.user_id     AS user_id,
                                        up.created_at  AS since
                                 FROM user_base u
                                          LEFT JOIN user_permissions up ON up.user_id = u.id
                                          LEFT JOIN permissions p ON up.permission_id = p.id)

SELECT u.id                                                                                 AS user_id,
       u.email,
       u.first_name,
       u.last_name,
       u.locked,
       u.two_fa_enabled,
       u.created_at                                                                         AS user_created_at,
       COALESCE(jsonb_agg(DISTINCT to_jsonb(r)) FILTER (WHERE r.user_id IS NOT NULL), '[]') AS roles,
       COALESCE(jsonb_agg(DISTINCT to_jsonb(p)) FILTER (WHERE p.user_id IS NOT NULL), '[]') AS permissions
FROM user_base u
         LEFT JOIN user_roles_joined AS r ON r.user_id = u.id
         LEFT JOIN user_permissions_joined AS p ON p.user_id = u.id
GROUP BY u.id, u.email, u.first_name, u.last_name, u.locked, u.two_fa_enabled, u.created_at
LIMIT sqlc.arg('size') OFFSET sqlc.arg('page');

-- name: LockUserById :one
WITH locked_user AS (UPDATE users
SET locked = true,
    locked_at = now()
    WHERE users.id = sqlc.arg('user_id')
    returning users.id)
INSERT
INTO user_security_actions(user_id, actor_id, action, ip_address, user_agent)
SELECT locked_user.id,
       sqlc.arg('actor_id'),
       'lock',
       sqlc.arg('ip_address'),
       sqlc.arg('user_agent')
FROM locked_user
RETURNING id;

-- name: UnlockUserById :one
WITH unlocked_user AS (
    UPDATE users
        SET locked = false,
            locked_at = now()
        WHERE users.id = sqlc.arg('user_id')
        returning users.id)
INSERT
INTO user_security_actions(user_id,
                           actor_id,
                           action,
                           ip_address,
                           user_agent)
SELECT unlocked_user.id,
       sqlc.arg('actor_id'),
       'unlock',
       sqlc.arg('ip_address'),
       sqlc.arg('user_agent')
FROM unlocked_user
RETURNING id;

-- name: DisableUserById :one
WITH disable_user AS (
    UPDATE users
        SET disabled = true,
            disabled_at = now()
        WHERE users.id = sqlc.arg('user_id')
        returning users.id)
INSERT
INTO user_security_actions(user_id,
                           actor_id,
                           action,
                           ip_address,
                           user_agent)
SELECT disable_user.id,
       sqlc.arg('actor_id'),
       'disable',
       sqlc.arg('ip_address'),
       sqlc.arg('user_agent')
FROM disable_user
RETURNING id;

-- name: EnableUserById :one
WITH enable_user AS (
    UPDATE users
        SET disabled = false,
            disabled_at = now()
        WHERE users.id = sqlc.arg('user_id')
        RETURNING users.id)
INSERT
INTO user_security_actions (user_id,
                            actor_id,
                            action,
                            ip_address,
                            user_agent)
SELECT enable_user.id,
       sqlc.arg('actor_id'),
       'enable',
       sqlc.arg('ip_address'),
       sqlc.arg('user_agent')
FROM enable_user
RETURNING id;