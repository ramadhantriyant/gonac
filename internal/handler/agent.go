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

	agentID := c.Get("agent_id").(string)
	status := "KNOWN"
	if !d.IsKnown {
		status = "UNKNOWN"
	}
	log.Printf("[%s] agent=%s MAC=%s IP=%s", status, agentID, d.MacAddress, d.IpAddress)

	return c.JSON(http.StatusCreated, created)
}

type policyTarget struct {
	MacAddress string `json:"mac_address"`
	IPAddress  string `json:"ip_address"`
}

// GetPolicy returns every currently-blocked device. The control plane
// doesn't track which agent owns which subnet, so it hands back the full
// blocklist and each agent filters to its own segment before enforcing —
// ARP poisoning can't reach off-segment devices anyway.
func (h *handler) GetPolicy(c *echo.Context) error {
	devices, err := h.st.ListBlockedDevices(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	blocked := make([]policyTarget, 0, len(devices))
	for _, d := range devices {
		blocked = append(blocked, policyTarget{MacAddress: d.MacAddress, IPAddress: d.IpAddress})
	}

	return c.JSON(http.StatusOK, map[string]any{"blocked": blocked})
}

func (h *handler) PostEnforcementEvent(c *echo.Context) error {
	var p struct {
		MacAddress string `json:"mac_address"`
		Action     string `json:"action"`
	}

	if err := c.Bind(&p); err != nil {
		return c.JSON(http.StatusBadRequest, badRequest)
	}

	agentID := c.Get("agent_id").(string)
	if err := h.st.RecordEnforcementEvent(c.Request().Context(), p.MacAddress, agentID, p.Action); err != nil {
		return c.JSON(http.StatusInternalServerError, internalServerError)
	}

	log.Printf("[ENFORCEMENT] agent=%s MAC=%s action=%s", agentID, p.MacAddress, p.Action)
	return c.JSON(http.StatusCreated, created)
}
