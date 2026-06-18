-- +goose Up
ALTER TABLE devices ADD COLUMN is_blocked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN blocked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_devices_is_blocked ON devices (is_blocked) WHERE is_blocked;

CREATE TABLE IF NOT EXISTS enforcement_events (
    id          UUID        PRIMARY KEY,
    device_id   UUID        NOT NULL REFERENCES devices(id),
    agent_id    TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enforcement_events_device ON enforcement_events (device_id);

-- +goose Down
DROP TABLE IF EXISTS enforcement_events;
DROP INDEX IF EXISTS idx_devices_is_blocked;
ALTER TABLE devices DROP COLUMN IF EXISTS blocked_at;
ALTER TABLE devices DROP COLUMN IF EXISTS is_blocked;
