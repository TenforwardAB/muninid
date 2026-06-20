-- +goose Up
ALTER TABLE oidc_clients
ADD COLUMN IF NOT EXISTS "postLogoutRedirectUris" jsonb NULL DEFAULT NULL;

-- +goose Down
ALTER TABLE oidc_clients
DROP COLUMN IF EXISTS "postLogoutRedirectUris";
