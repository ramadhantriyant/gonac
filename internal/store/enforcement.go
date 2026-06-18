package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ramadhantriyant/gonac/internal/store/database"
)

// RecordEnforcementEvent logs an audit entry for an enforcement action an
// agent took against a device (block started, block stopped, heal sent).
func (s *Store) RecordEnforcementEvent(ctx context.Context, macAddress, agentID, action string) error {
	device, err := s.querier.GetDeviceByMAC(ctx, macAddress)
	if err != nil {
		return fmt.Errorf("store: record enforcement event: %w", err)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("store: record enforcement event: %w", err)
	}

	_, err = s.querier.CreateEnforcementEvent(ctx, database.CreateEnforcementEventParams{
		ID:       id,
		DeviceID: device.ID,
		AgentID:  agentID,
		Action:   action,
	})
	if err != nil {
		return fmt.Errorf("store: record enforcement event: %w", err)
	}
	return nil
}
