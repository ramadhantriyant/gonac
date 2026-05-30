package handler

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

func (h *handler) ListDevices(c *echo.Context) error {
	devices, err := h.st.ListDevices(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}
	return c.JSON(http.StatusOK, devices)
}
