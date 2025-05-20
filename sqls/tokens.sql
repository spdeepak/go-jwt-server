-- name: SaveToken :exec
INSERT INTO tokens (token,
                    refresh_token,
                    token_expires_at,
                    refresh_expires_at,
                    ip_address,
                    user_agent,
                    device_name,
                    created_by)
VALUES (sqlc.arg('token'),
        sqlc.arg('refresh_token'),
        sqlc.arg('token_expires_at'),
        sqlc.arg('refresh_expires_at'),
        sqlc.arg('ip_address'),
        sqlc.arg('user_agent'),
        sqlc.arg('device_name'),
        sqlc.arg('created_by'));

-- name: RevokeBearerToken :exec
UPDATE tokens
SET revoked = true
WHERE token = sqlc.arg('token');

-- name: RevokeRefreshToken :exec
UPDATE tokens
SET revoked = true
WHERE refresh_token = sqlc.arg('refresh_token');

-- name: GetByBearerToken :one
SELECT *
FROM tokens
WHERE token = sqlc.arg('token');

-- name: GetByRefreshToken :one
SELECT *
FROM tokens
WHERE refresh_token = sqlc.arg('refresh_token');
