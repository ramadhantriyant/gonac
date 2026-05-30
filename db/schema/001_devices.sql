-- +goose Up
CREATE TABLE IF NOT EXISTS devices (
    id          UUID        PRIMARY KEY,
    mac_address TEXT        NOT NULL UNIQUE,
    ip_address  TEXT        NOT NULL,
    hostname    TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_known    BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_devices_mac       ON devices (mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_ip        ON devices (ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_devices_last_seen;
DROP INDEX IF EXISTS idx_devices_ip;
DROP INDEX IF EXISTS idx_devices_mac;
DROP TABLE IF EXISTS devices;
