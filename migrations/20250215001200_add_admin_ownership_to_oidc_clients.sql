-- +goose Up
ALTER TABLE oidc_clients
ADD COLUMN IF NOT EXISTS "customerId" varchar(255) NULL DEFAULT NULL,
ADD COLUMN IF NOT EXISTS "createdBySubject" varchar(255) NULL DEFAULT NULL,
ADD COLUMN IF NOT EXISTS "createdByEmail" varchar(320) NULL DEFAULT NULL;

CREATE INDEX IF NOT EXISTS oidc_clients_customerId_idx ON oidc_clients ("customerId");

-- +goose Down
DROP INDEX IF EXISTS oidc_clients_customerId_idx;
ALTER TABLE oidc_clients
DROP COLUMN IF EXISTS "createdByEmail",
DROP COLUMN IF EXISTS "createdBySubject",
DROP COLUMN IF EXISTS "customerId";
