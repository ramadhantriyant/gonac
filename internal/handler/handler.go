package handler

import "github.com/ramadhantriyant/gonac/internal/store"

type handler struct {
	st *store.Store
}

var (
	created             = map[string]string{"message": "created"}
	badRequest          = map[string]string{"message": "bad request"}
	unauthorized        = map[string]string{"message": "unauthorized"}
	internalServerError = map[string]string{"message": "internal server error"}
)

func NewHandler(s *store.Store) *handler {
	return &handler{st: s}
}
