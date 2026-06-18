package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ramadhantriyant/gonac/internal/store/database"
)

func (s *Store) UpsertDevice(ctx context.Context, mac, ip string, hostname *string) (database.Device, error) {
	id, err := uuid.NewV7()
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

func (s *Store) MarkDeviceKnown(ctx context.Context, deviceID string) (database.Device, error) {
	id, err := uuid.Parse(deviceID)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: mark device known: %w", err)
	}

	device, err := s.querier.GetDeviceByID(ctx, id)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: mark device known: %w", err)
	}

	_, err = s.querier.MarkDeviceKnown(ctx, device.MacAddress)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: mark device known: %w", err)
	}
	return device, nil
}

func (s *Store) GetDeviceByID(ctx context.Context, deviceID string) (database.Device, error) {
	id, err := uuid.Parse(deviceID)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: get device by id: %w", err)
	}

	device, err := s.querier.GetDeviceByID(ctx, id)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: get device by id: %w", err)
	}
	return device, nil
}

func (s *Store) GetDeviceByMac(ctx context.Context, macAddress string) (database.Device, error) {
	device, err := s.querier.GetDeviceByMAC(ctx, macAddress)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: get device by mac: %w", err)
	}
	return device, nil
}

func (s *Store) ListBlockedDevices(ctx context.Context) ([]database.Device, error) {
	return s.querier.ListBlockedDevices(ctx)
}

func (s *Store) BlockDevice(ctx context.Context, macAddress string) (database.Device, error) {
	device, err := s.querier.BlockDeviceByMAC(ctx, macAddress)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: block device: %w", err)
	}
	return device, nil
}

func (s *Store) UnblockDevice(ctx context.Context, macAddress string) (database.Device, error) {
	device, err := s.querier.UnblockDeviceByMAC(ctx, macAddress)
	if err != nil {
		return database.Device{}, fmt.Errorf("store: unblock device: %w", err)
	}
	return device, nil
}
