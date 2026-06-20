-- +goose Up
CREATE TABLE IF NOT EXISTS oidc_adapter_store (
    id varchar(128) PRIMARY KEY,
    name varchar(64) NOT NULL,
    payload jsonb NOT NULL,
    "grantId" varchar(128) NULL,
    "userCode" varchar(128) NULL UNIQUE,
    uid varchar(128) NULL UNIQUE,
    "expiresAt" timestamptz NULL,
    "consumedAt" timestamptz NULL,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oidc_adapter_store_name_idx ON oidc_adapter_store (name);
CREATE INDEX IF NOT EXISTS oidc_adapter_store_grantId_idx ON oidc_adapter_store ("grantId");
CREATE INDEX IF NOT EXISTS oidc_adapter_store_expiresAt_idx ON oidc_adapter_store ("expiresAt");

-- +goose Down
DROP TABLE IF EXISTS oidc_adapter_store;
