-- name: CreateEnforcementEvent :one
INSERT INTO enforcement_events (id, device_id, agent_id, action)
VALUES ($1, $2, $3, $4)
RETURNING *;
