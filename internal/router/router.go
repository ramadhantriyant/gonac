package router

import (
	"crypto/x509"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/ramadhantriyant/gonac/internal/handler"
	"github.com/ramadhantriyant/gonac/internal/store"
	webui "github.com/ramadhantriyant/gonac/internal/ui"
)

func NewRouter(s *store.Store) *echo.Echo {
	r := echo.New()
	r.Use(middleware.RequestLogger(), mtlsMiddleware())
	h := handler.NewHandler(s)

	r.POST("/device", h.UpsertDevice)

	return r
}

func NewAdminRouter(s *store.Store) *echo.Echo {
	r := echo.New()
	r.Use(middleware.RequestLogger())
	h := handler.NewHandler(s)

	api := r.Group("/api", middleware.RequestID())
	{
		d := api.Group("/devices")
		{
			d.GET("", h.ListDevices)
			d.GET("/id/:id", h.GetDeviceByID)
			d.GET("/mac/:mac", h.GetDeviceByMAC)

			d.PUT("/id/:id/known", h.MarkAsKnown)
			d.PUT("/mac/:mac/known", h.MarkAsKnownByMAC)
		}
	}

	sub, err := fs.Sub(webui.FS, "dist")
	if err != nil {
		log.Fatalf("error finding built ui: %v", err)
	}
	r.GET("/*", spaHandler(sub))
	r.GET("/", spaHandler(sub))

	return r
}

func spaHandler(fsys fs.FS) echo.HandlerFunc {
	srv := http.FileServer(http.FS(fsys))
	index, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		log.Fatalf("ui: index.html not found in embedded FS: %v", err)
	}
	return func(c *echo.Context) error {
		path := strings.TrimPrefix(c.Request().URL.Path, "/")
		if path != "" {
			if stat, err := fs.Stat(fsys, path); err == nil && !stat.IsDir() {
				srv.ServeHTTP(c.Response(), c.Request())
				return nil
			}
		}
		return c.HTMLBlob(http.StatusOK, index)
	}
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
