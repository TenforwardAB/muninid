-- +goose Up
CREATE TABLE IF NOT EXISTS login_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "attemptKey" varchar(512) NOT NULL UNIQUE,
    "keyType" varchar(32) NOT NULL,
    "failureCount" integer NOT NULL DEFAULT 0,
    "lockedUntil" timestamptz NULL,
    "firstFailureAt" timestamptz NOT NULL DEFAULT now(),
    "lastFailureAt" timestamptz NOT NULL DEFAULT now(),
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS login_attempts_type_locked_idx ON login_attempts ("keyType", "lockedUntil");

-- +goose Down
DROP TABLE IF EXISTS login_attempts;
