-- name: CreateTOTP :exec
WITH revoke_old_totp AS (
    UPDATE users_2fa
        SET revoked = true
            WHERE users_2fa.user_email = sqlc.arg('revoke_email')
)
INSERT INTO users_2fa (user_email, secret, url, created_at)
VALUES (sqlc.arg('email'), sqlc.arg('secret'), sqlc.arg('url'), now());

-- name: GetSecret :one
SELECT *
FROM users_2fa
WHERE user_email = sqlc.arg('email')
  AND revoked = false;

-- name: DeleteSecret :exec
DELETE
FROM users_2fa
WHERE user_email = sqlc.arg('email')
  AND secret = sqlc.arg('secret');