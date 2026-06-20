-- +goose Up
CREATE TABLE IF NOT EXISTS oidc_clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "clientId" varchar(128) NOT NULL UNIQUE,
    "clientSecret" varchar(256) NOT NULL,
    name varchar(255) NOT NULL,
    "redirectUris" jsonb NOT NULL,
    "grantTypes" jsonb NOT NULL,
    scopes jsonb NOT NULL,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS oidc_clients_clientId_idx ON oidc_clients ("clientId");

-- +goose Down
DROP TABLE IF EXISTS oidc_clients;
