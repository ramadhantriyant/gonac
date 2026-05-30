package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/ramadhantriyant/gonac/internal/store/database"
)

func (s *Store) UpsertDevice(ctx context.Context, mac, ip string, hostname *string) (database.Device, error) {
	id, err := newUUID()
	if err != nil {
		return database.Device{}, fmt.Errorf("store: upsert: %w", err)
	}
	return s.querier.UpsertDevice(ctx, database.UpsertDeviceParams{
		ID:         id,
		MacAddress: mac,
		IpAddress:  ip,
		Hostname:   hostname,
	})
}

func (s *Store) ListDevices(ctx context.Context) ([]database.Device, error) {
	return s.querier.ListDevices(ctx)
}

func (s *Store) ListUnknownDevices(ctx context.Context) ([]database.Device, error) {
	return s.querier.ListUnknownDevices(ctx)
}

func newUUID() (pgtype.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}
