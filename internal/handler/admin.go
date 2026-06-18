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

func (h *handler) GetDeviceByID(c *echo.Context) error {
	id := c.Param("id")
	device, err := h.st.GetDeviceByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	return c.JSON(http.StatusOK, device)
}

func (h *handler) GetDeviceByMAC(c *echo.Context) error {
	mac := c.Param("mac")
	device, err := h.st.GetDeviceByMac(c.Request().Context(), mac)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	return c.JSON(http.StatusOK, device)
}

func (h *handler) MarkAsKnown(c *echo.Context) error {
	id := c.Param("id")
	device, err := h.st.MarkDeviceKnown(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	return c.JSON(http.StatusOK, device)
}

func (h *handler) MarkAsKnownByMAC(c *echo.Context) error {
	mac := c.Param("mac")
	device, err := h.st.GetDeviceByMac(c.Request().Context(), mac)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	_, err = h.st.MarkDeviceKnown(c.Request().Context(), device.ID.String())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	return c.JSON(http.StatusOK, device)
}

func (h *handler) ListBlockedDevices(c *echo.Context) error {
	devices, err := h.st.ListBlockedDevices(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}
	return c.JSON(http.StatusOK, devices)
}

func (h *handler) BlockDeviceByMAC(c *echo.Context) error {
	mac := c.Param("mac")
	device, err := h.st.BlockDevice(c.Request().Context(), mac)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}
	return c.JSON(http.StatusOK, device)
}

func (h *handler) UnblockDeviceByMAC(c *echo.Context) error {
	mac := c.Param("mac")
	device, err := h.st.UnblockDevice(c.Request().Context(), mac)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}
	return c.JSON(http.StatusOK, device)
}
