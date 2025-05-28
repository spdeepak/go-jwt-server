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