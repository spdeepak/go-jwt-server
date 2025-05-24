-- name: SaveToken :exec
INSERT INTO tokens (token,
                    refresh_token,
                    token_expires_at,
                    refresh_expires_at,
                    ip_address,
                    user_agent,
                    device_name,
                    email,
                    created_by)
VALUES (sqlc.arg('token'),
        sqlc.arg('refresh_token'),
        sqlc.arg('token_expires_at'),
        sqlc.arg('refresh_expires_at'),
        sqlc.arg('ip_address'),
        sqlc.arg('user_agent'),
        sqlc.arg('device_name'),
        sqlc.arg('email'),
        sqlc.arg('created_by'));

-- name: RevokeBearerToken :exec
UPDATE tokens
SET revoked    = TRUE,
    revoked_at = now()
WHERE token = sqlc.arg('token');

-- name: RevokeRefreshToken :exec
UPDATE tokens
SET revoked    = TRUE,
    revoked_at = now()
WHERE refresh_token = sqlc.arg('refresh_token');

-- name: RevokeAllTokens :exec
UPDATE tokens
SET revoked    = TRUE,
    revoked_at = now()
WHERE email = sqlc.arg('email');

-- name: GetByBearerToken :one
SELECT *
FROM tokens
WHERE token = sqlc.arg('token');

-- name: GetByRefreshToken :one
SELECT *
FROM tokens
WHERE refresh_token = sqlc.arg('refresh_token');

-- name: IsBearerValid :one
SELECT 1
FROM tokens
WHERE token = sqlc.arg('token')
  AND ip_address = sqlc.arg('ip_address')
  AND user_agent = sqlc.arg('user_agent')
  AND device_name = sqlc.arg('device_name')
  AND revoked = FALSE;

-- name: IsRefreshValid :one
SELECT 1
FROM tokens
WHERE refresh_token = sqlc.arg('refresh_token')
  AND ip_address = sqlc.arg('ip_address')
  AND user_agent = sqlc.arg('user_agent')
  AND device_name = sqlc.arg('device_name')
  AND revoked = FALSE;

-- name: RefreshAndInvalidateToken :exec
WITH revoked_token AS (
    UPDATE tokens
        SET revoked = TRUE,
            revoked_at = now()
        WHERE tokens.refresh_token = sqlc.arg('old_refresh_token')
        RETURNING 1)
INSERT
INTO tokens (token,
             refresh_token,
             token_expires_at,
             refresh_expires_at,
             ip_address,
             user_agent,
             device_name,
             email,
             created_by)
VALUES (sqlc.arg('new_token'),
        sqlc.arg('new_refresh_token'),
        sqlc.arg('token_expires_at'),
        sqlc.arg('refresh_expires_at'),
        sqlc.arg('ip_address'),
        sqlc.arg('user_agent'),
        sqlc.arg('device_name'),
        sqlc.arg('email'),
        sqlc.arg('created_by'));

-- name: ListAllActiveSessions :many
SELECT *
FROM tokens
WHERE email = sqlc.arg('email')
  AND revoked = false
  AND refresh_expires_at > now();