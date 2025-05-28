-- name: Setup2FA :exec
WITH revoke_old_2fa AS (
UPDATE users_2fa
SET revoked = true
WHERE users_2fa.user_id = sqlc.arg('revoke_user_id') ), setup_new_2fa AS(
INSERT
INTO users_2fa (user_id, secret, url, created_at)
VALUES (sqlc.arg('user_id'), sqlc.arg('secret'), sqlc.arg('url'), now())
)
UPDATE users
SET two_fa_enabled = true
WHERE users.id = sqlc.arg('user_id');


-- name: Get2FADetails :one
SELECT *
FROM users_2fa
WHERE user_id = sqlc.arg('user_id')
  AND revoked = false;

-- name: Delete2FA :exec
DELETE
FROM users_2fa
WHERE user_id = sqlc.arg('user_id')
  AND secret = sqlc.arg('secret');