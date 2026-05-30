package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ramadhantriyant/gonac/internal/store/database"
)

type Store struct {
	pool    *pgxpool.Pool
	querier database.Querier
}

func New(ctx context.Context, dbURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}

	return &Store{
		pool:    pool,
		querier: database.New(pool),
	}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}
