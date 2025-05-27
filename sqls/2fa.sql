-- name: CreateTOTP :exec
WITH revoke_old_totp AS (
UPDATE users_2fa
SET revoked = true
WHERE users_2fa.user_id = sqlc.arg('revoke_user_id')
    )
INSERT
INTO users_2fa (user_id, secret, url, created_at)
VALUES (sqlc.arg('user_id'), sqlc.arg('secret'), sqlc.arg('url'), now());

-- name: GetSecret :one
SELECT *
FROM users_2fa
WHERE user_id = sqlc.arg('user_id')
  AND revoked = false;

-- name: DeleteSecret :exec
DELETE
FROM users_2fa
WHERE user_id = sqlc.arg('user_id')
  AND secret = sqlc.arg('secret');