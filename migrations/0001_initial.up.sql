CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS jwt_secrets
(
    id          UUID PRIMARY KEY     DEFAULT uuid_generate_v4(),
    secret      TEXT        NOT NULL,
    secret_type TEXT        NOT NULL DEFAULT 'default',
    is_valid    BOOLEAN              default TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users
(
    email      TEXT PRIMARY KEY,
    first_name TEXT        NOT NULL,
    last_name  TEXT        NOT NULL,
    password   TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS users_email ON users (email);

CREATE TABLE IF NOT EXISTS tokens
(
    token              TEXT PRIMARY KEY,
    refresh_token      TEXT        NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_expires_at   TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    revoked            BOOLEAN              DEFAULT FALSE,
    revoked_at         TIMESTAMPTZ,
    ip_address         TEXT        NOT NULL,
    user_agent         TEXT        NOT NULL,
    device_name        TEXT        NOT NULL,
    created_by         TEXT        NOT NULL --Source of request web/mobile/api
);

CREATE INDEX IF NOT EXISTS tokens_token ON tokens (token);
CREATE INDEX IF NOT EXISTS tokens_refresh_token ON tokens (refresh_token);
