-- +goose Up
CREATE TABLE IF NOT EXISTS token_exchange_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "clientId" varchar(128) NOT NULL,
    priority integer NOT NULL DEFAULT 0,
    subject varchar(255) NULL,
    "subjectTokenTypes" jsonb NOT NULL DEFAULT '[]'::jsonb,
    audiences jsonb NOT NULL DEFAULT '[]'::jsonb,
    scopes jsonb NULL,
    "actorTokenRequired" boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    description text NULL,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS token_exchange_policies_client_priority_idx ON token_exchange_policies ("clientId", priority);
CREATE INDEX IF NOT EXISTS token_exchange_policies_client_subject_idx ON token_exchange_policies ("clientId", subject);

-- +goose Down
DROP TABLE IF EXISTS token_exchange_policies;
