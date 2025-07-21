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
                   WHERE users.email = sqlc.arg('email')),
     user_roles_joined AS (SELECT r.*
                           FROM user_roles as ur
                                    JOIN roles r ON ur.role_id = r.id
                                    JOIN user_base u ON ur.user_id = u.id),
     role_permissions_joined AS (SELECT p.*
                                 FROM role_permissions as rp
                                          JOIN permissions p ON rp.permission_id = p.id
                                          JOIN user_roles_joined r ON rp.role_id = r.id),
     user_permissions_joined AS (SELECT p.*
                                 FROM user_permissions as up
                                          JOIN permissions p ON up.permission_id = p.id
                                          JOIN user_base u ON up.user_id = u.id),
     all_permissions AS (SELECT *
                         FROM role_permissions_joined
                         UNION
                         SELECT *
                         FROM user_permissions_joined)

SELECT u.id         AS user_id,
       u.email,
       u.password,
       u.first_name,
       u.last_name,
       u.locked,
       u.two_fa_enabled,
       u.created_at AS user_created_at,
       r.name       AS role_name,
       p.name       AS permission_name
FROM user_base u
         LEFT JOIN user_roles_joined r ON TRUE
         LEFT JOIN all_permissions p ON TRUE;