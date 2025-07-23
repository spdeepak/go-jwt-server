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
     user_roles_joined AS (SELECT r.name AS role_name, ur.user_id
                           FROM user_base u
                                    LEFT JOIN user_roles ur ON ur.user_id = u.id
                                    LEFT JOIN roles r ON ur.role_id = r.id),
     role_permissions_joined AS (SELECT p.name AS permission_name, ur.user_id
                                 FROM user_roles_joined urj
                                          JOIN user_roles ur ON ur.user_id = urj.user_id
                                          JOIN role_permissions rp ON rp.role_id = ur.role_id
                                          JOIN permissions p ON p.id = rp.permission_id),
     user_permissions_joined AS (SELECT p.name AS permission_name, up.user_id
                                 FROM user_base u
                                          LEFT JOIN user_permissions up ON up.user_id = u.id
                                          LEFT JOIN permissions p ON up.permission_id = p.id),
     all_permissions AS (SELECT *
                         FROM role_permissions_joined
                         UNION
                         SELECT *
                         FROM user_permissions_joined)

SELECT u.id                                                       AS user_id,
       u.email,
       u.password,
       u.first_name,
       u.last_name,
       u.locked,
       u.two_fa_enabled,
       u.created_at                                               AS user_created_at,
       COALESCE(STRING_AGG(DISTINCT r.role_name, ', '), '')       AS role_names,
       COALESCE(STRING_AGG(DISTINCT p.permission_name, ', '), '') AS permission_names
FROM user_base u
         LEFT JOIN user_roles_joined r ON r.user_id = u.id
         LEFT JOIN all_permissions p ON p.user_id = u.id
GROUP BY u.id, u.email, u.password, u.first_name, u.last_name;