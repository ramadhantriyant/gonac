-- name: UpsertDevice :one
INSERT INTO devices (id, mac_address, ip_address, hostname, first_seen, last_seen)
VALUES ($1, $2, $3, $4, NOW(), NOW())
ON CONFLICT (mac_address)
DO UPDATE SET
    ip_address = EXCLUDED.ip_address,
    hostname   = COALESCE(EXCLUDED.hostname, devices.hostname),
    last_seen  = NOW()
RETURNING *;

-- name: ListDevices :many
SELECT id, mac_address, ip_address, hostname, first_seen, last_seen, is_known
FROM devices
ORDER BY last_seen DESC;

-- name: ListUnknownDevices :many
SELECT id, mac_address, ip_address, hostname, first_seen, last_seen, is_known
FROM devices
WHERE is_known = FALSE
ORDER BY last_seen DESC;

-- name: GetDeviceByMAC :one
SELECT id, mac_address, ip_address, hostname, first_seen, last_seen, is_known
FROM devices
WHERE mac_address = $1;

-- name: MarkDeviceKnown :one
UPDATE devices
SET is_known = TRUE
WHERE mac_address = $1
RETURNING *;
