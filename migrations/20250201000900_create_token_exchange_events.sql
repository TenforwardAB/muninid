-- +goose Up
CREATE TABLE IF NOT EXISTS token_exchange_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "clientId" varchar(128) NOT NULL,
    "policyId" uuid NULL,
    subject varchar(255) NULL,
    "subjectTokenType" varchar(255) NOT NULL,
    "subjectTokenId" varchar(255) NULL,
    "requestedAudience" varchar(512) NULL,
    "grantedAudience" varchar(512) NULL,
    "requestedScopes" jsonb NULL,
    "grantedScopes" jsonb NULL,
    "actorSubject" varchar(255) NULL,
    success boolean NOT NULL DEFAULT false,
    error text NULL,
    "issuedTokenId" varchar(255) NULL,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS token_exchange_events_client_created_idx ON token_exchange_events ("clientId", "createdAt");

-- +goose Down
DROP TABLE IF EXISTS token_exchange_events;
