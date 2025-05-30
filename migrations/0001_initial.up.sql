CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Multi-Tenant
CREATE TABLE IF NOT EXISTS tenants
(
    id   VARCHAR(100) PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT no_spaces CHECK (id NOT LIKE '% %')
);

CREATE TABLE IF NOT EXISTS jwt_secrets
(
    id          UUID PRIMARY KEY     DEFAULT uuid_generate_v4(),
    secret      TEXT        NOT NULL,
    secret_type TEXT        NOT NULL DEFAULT 'default',
    is_valid    BOOLEAN     NOT NULL default TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users
(
    id             UUID PRIMARY KEY     DEFAULT uuid_generate_v4(),
    email          TEXT        NOT NULL UNIQUE,
    first_name     TEXT        NOT NULL,
    last_name      TEXT        NOT NULL,
    password       TEXT        NOT NULL,
    locked         BOOLEAN     NOT NULL DEFAULT FALSE,
    two_fa_enabled BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS users_email ON users (email);

CREATE TABLE IF NOT EXISTS users_password
(
    user_id    UUID        NOT NULL,
    password   TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users_2fa
(
    id         UUID PRIMARY KEY     DEFAULT uuid_generate_v4(),
    user_id    UUID        NOT NULL,
    secret     TEXT        NOT NULL,
    url        TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX unique_active_totp_per_user
    ON users_2fa (user_id)
    WHERE revoked = false;

CREATE TABLE IF NOT EXISTS tokens
(
    token              TEXT PRIMARY KEY,
    refresh_token      TEXT        NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_expires_at   TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    revoked            BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at         TIMESTAMPTZ,
    email              TEXT        NOT NULL,
    ip_address         TEXT        NOT NULL,
    user_agent         TEXT        NOT NULL,
    device_name        TEXT        NOT NULL,
    created_by         TEXT        NOT NULL --Source of request web/mobile/api
);

CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens (token);
CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens (refresh_token);
CREATE INDEX IF NOT EXISTS idx_tokens_email ON tokens (email);
CREATE INDEX IF NOT EXISTS idx_bearer_valid ON tokens (token, ip_address, user_agent, device_name, revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_valid ON tokens (refresh_token, ip_address, user_agent, device_name, revoked);

-- Roles per tenant
CREATE TABLE roles
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    UNIQUE (tenant_id, name)
);

-- Permissions per tenant
CREATE TABLE permissions
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    UNIQUE (tenant_id, name)
);

-- Role to Permission mapping (per tenant)
CREATE TABLE role_permissions
(
    tenant_id     UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    role_id       UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (tenant_id, role_id, permission_id)
);

-- User to Role mapping (per tenant)
CREATE TABLE user_roles
(
    tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id   UUID NOT NULL,
    role_id   UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (tenant_id, user_id, role_id)
);

-- Per-user permission overrides (per tenant)
CREATE TABLE user_permission_grants
(
    tenant_id     UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id       UUID        NOT NULL,
    permission_id UUID        NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    grant_type    VARCHAR(10) NOT NULL CHECK (grant_type IN ('grant', 'deny')),
    PRIMARY KEY (tenant_id, user_id, permission_id)
);