package router

import (
	"crypto/x509"
	"net"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/ramadhantriyant/gonac/internal/handler"
	"github.com/ramadhantriyant/gonac/internal/store"
)

func NewRouter(s *store.Store) *echo.Echo {
	r := echo.New()
	h := handler.NewHandler(s)

	r.POST("/device", h.UpsertDevice, mtlsMiddleware())

	return r
}

func NewAdminRouter(s *store.Store) *echo.Echo {
	r := echo.New()
	h := handler.NewHandler(s)

	api := r.Group("/api")
	api.GET("/devices", h.ListDevices)

	return r
}

// mtlsMiddleware verifies that the client certificate CN matches the
// X-Agent-ID header and that the connection IP is listed in the cert SANs.
// TLS chain and expiry verification is handled by the http.Server.
func mtlsMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			r := c.Request()

			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "client certificate required"})
			}

			cert := r.TLS.PeerCertificates[0]
			agentID := r.Header.Get("X-Agent-ID")

			if cert.Subject.CommonName != agentID {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "agent ID mismatch"})
			}

			remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"message": "invalid remote address"})
			}
			if !certContainsIP(cert, net.ParseIP(remoteIP)) {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "IP not in certificate"})
			}

			c.Set("agent_id", agentID)
			return next(c)
		}
	}
}

func certContainsIP(cert *x509.Certificate, ip net.IP) bool {
	for _, san := range cert.IPAddresses {
		if san.Equal(ip) {
			return true
		}
	}
	return false
}
