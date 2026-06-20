-- +goose Up
CREATE TABLE IF NOT EXISTS identity_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name varchar(255) NOT NULL,
    "targetType" varchar(32) NOT NULL,
    "targetId" uuid NULL,
    policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS identity_policies_target_idx ON identity_policies ("targetType", "targetId");

-- +goose Down
DROP TABLE IF EXISTS identity_policies;
