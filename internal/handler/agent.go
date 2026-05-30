package handler

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v5"
)

func (h *handler) UpsertDevice(c *echo.Context) error {
	var p struct {
		MacAddress string  `json:"mac_address"`
		IPAddress  string  `json:"ip_address"`
		Hostname   *string `json:"hostname"`
	}

	if err := c.Bind(&p); err != nil {
		return c.JSON(http.StatusBadRequest, badRequest)
	}

	d, err := h.st.UpsertDevice(c.Request().Context(), p.MacAddress, p.IPAddress, p.Hostname)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	agentID, _ := c.Get("agent_id").(string)
	status := "KNOWN"
	if !d.IsKnown {
		status = "UNKNOWN"
	}
	log.Printf("[%s] agent=%s MAC=%s IP=%s", status, agentID, d.MacAddress, d.IpAddress)

	return c.JSON(http.StatusCreated, created)
}
