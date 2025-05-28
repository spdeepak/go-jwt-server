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