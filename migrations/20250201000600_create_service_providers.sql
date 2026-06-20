-- +goose Up
CREATE TABLE IF NOT EXISTS saml_service_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "entityId" varchar(512) NOT NULL UNIQUE,
    "metadataXml" text NULL,
    "acsEndpoints" jsonb NOT NULL DEFAULT '[]'::jsonb,
    binding varchar(64) NOT NULL,
    "attributeMapping" jsonb NOT NULL DEFAULT '{}'::jsonb,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS saml_service_providers_entityId_idx ON saml_service_providers ("entityId");

-- +goose Down
DROP TABLE IF EXISTS saml_service_providers;
