CREATE TABLE users (
    user_id        UUID PRIMARY KEY,
    email          VARCHAR(255) NOT NULL,
    password_hash  TEXT NOT NULL,
    role           VARCHAR(100) NOT NULL REFERENCES roles(role_name),
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login     TIMESTAMPTZ,
    CONSTRAINT uq_user_email UNIQUE (email)
);