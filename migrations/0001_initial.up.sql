-- JWT Secrets
CREATE TABLE IF NOT EXISTS jwt_secrets
(
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    secret      TEXT        NOT NULL,
    secret_type TEXT        NOT NULL DEFAULT 'default',
    is_valid    BOOLEAN     NOT NULL default TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users
CREATE TABLE IF NOT EXISTS users
(
    id         UUID PRIMARY KEY     DEFAULT uuidv7(),
    email          TEXT        NOT NULL UNIQUE,
    first_name     TEXT        NOT NULL,
    last_name      TEXT        NOT NULL,
    password       TEXT        NOT NULL,
    locked         BOOLEAN     NOT NULL DEFAULT FALSE,
    two_fa_enabled BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Password History
CREATE TABLE IF NOT EXISTS users_password
(
    user_id    UUID        NOT NULL,
    password   TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- 2FA
CREATE TABLE IF NOT EXISTS users_2fa
(
    id         UUID PRIMARY KEY     DEFAULT uuidv7(),
    user_id    UUID        NOT NULL,
    secret     TEXT        NOT NULL,
    url        TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS unique_active_totp_per_user
    ON users_2fa (user_id)
    WHERE revoked = false;

-- Roles
CREATE TABLE IF NOT EXISTS roles
(
    id         UUID PRIMARY KEY     DEFAULT uuidv7(),
    name        TEXT        NOT NULL UNIQUE, -- e.g., "admin", "user"
    description TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT        NOT NULL

);

-- Permissions
CREATE TABLE IF NOT EXISTS permissions
(
    id         UUID PRIMARY KEY     DEFAULT uuidv7(),
    name        TEXT        NOT NULL UNIQUE, -- e.g., "user:read"
    description TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by  TEXT        NOT NULL
);

-- Role → Permissions
CREATE TABLE IF NOT EXISTS role_permissions
(
    role_id       UUID        NOT NULL,
    permission_id UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT        NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    CONSTRAINT fk_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions (role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions (permission_id);

-- User → Roles
CREATE TABLE IF NOT EXISTS user_roles
(
    user_id    UUID        NOT NULL,
    role_id    UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT        NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles (role_id);

-- User → Permissions (optional overrides)
CREATE TABLE IF NOT EXISTS user_permissions
(
    user_id       UUID        NOT NULL,
    permission_id UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT        NOT NULL,
    PRIMARY KEY (user_id, permission_id),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions (user_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_permission_id ON user_permissions (permission_id);

-- Tokens
CREATE TABLE IF NOT EXISTS tokens
(
    token              TEXT PRIMARY KEY,
    refresh_token      TEXT        NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_expires_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    refresh_expires_at TIMESTAMPTZ NOT NULL DEFAULT now(),
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

-- Create Admin User
INSERT INTO users(email, first_name, last_name, password, two_fa_enabled)
VALUES ('admin@localhost', 'Admin', 'User', '$2a$10$dg5hjvb7RQOLP6uwXBQeweQhwnJZBbOBn7oQHf0fY80oxuHu9ess6', false);

-- Create admin role and multiple permissions, assign them
WITH new_role AS (
    INSERT INTO roles (name, description, created_by, updated_by)
        VALUES ('super_admin', 'Super administrator role', 'system', 'system')
        RETURNING id),
     new_permissions AS (
         INSERT INTO permissions (name, description, created_by, updated_by)
             VALUES ('roles:create', 'Permission to create roles', 'system', 'system'),
                    ('roles:read', 'Permission to read roles', 'system', 'system'),
                    ('roles:update', 'Permission to update roles', 'system', 'system'),
                    ('roles:delete', 'Permission to delete roles', 'system', 'system'),
                    ('roles:user_assign', 'Permission to assign roles to user', 'system', 'system'),
                    ('roles:user_unassign', 'Permission to unassign roles to user', 'system', 'system'),
                    ('roles:permission_assign', 'Permission to assign permissions to roles', 'system', 'system'),
                    ('roles:permission_unassign', 'Permission to unassign permissions to roles', 'system', 'system'),
                    -- Default Permissions related to permissions
                    ('permissions:create', 'Permission to create permissions', 'system', 'system'),
                    ('permissions:read', 'Permission to read permissions', 'system', 'system'),
                    ('permissions:update', 'Permission to update permissions', 'system', 'system'),
                    ('permissions:delete', 'Permission to delete permissions', 'system', 'system'),
                    -- Default Permissions related to users
                    ('users:create', 'Permission to create users', 'system', 'system'),
                    ('users:read', 'Permission to read users', 'system', 'system'),
                    ('users:update', 'Permission to update users', 'system', 'system'),
                    ('users:delete', 'Permission to delete users', 'system', 'system'),
                    ('users:roles_assign', 'Permission to assign roles to users', 'system', 'system'),
                    ('users:roles_unassign', 'Permission to unassign roles to users', 'system', 'system')
             RETURNING id)
INSERT
INTO role_permissions (role_id, permission_id, created_by)
SELECT r.id, p.id, 'system'
FROM new_role r
         CROSS JOIN new_permissions p;

WITH admin_user AS (
    SELECT id FROM users WHERE email = 'admin@localhost'
),
     admin_role AS (
         SELECT id FROM roles WHERE name = 'super_admin'
     )
INSERT INTO user_roles (user_id, role_id, created_by)
SELECT u.id, r.id, 'system'
FROM admin_user u
         CROSS JOIN admin_role r;