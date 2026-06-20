-- +goose Up
CREATE TABLE IF NOT EXISTS admin_audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "actorSubject" varchar(255) NULL,
    "actorEmail" varchar(320) NULL,
    "customerId" varchar(255) NULL,
    action varchar(128) NOT NULL,
    "targetType" varchar(64) NOT NULL,
    "targetId" varchar(255) NULL,
    "authType" varchar(32) NOT NULL,
    ip varchar(128) NULL,
    "userAgent" text NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_audit_events_customerId_createdAt_idx ON admin_audit_events ("customerId", "createdAt");
CREATE INDEX IF NOT EXISTS admin_audit_events_actorSubject_createdAt_idx ON admin_audit_events ("actorSubject", "createdAt");

-- +goose Down
DROP TABLE IF EXISTS admin_audit_events;
