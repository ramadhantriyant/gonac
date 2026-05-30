package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/labstack/echo/v5"
)

type Server struct {
	srv      *http.Server
	certFile string
	keyFile  string
}

func New(e *echo.Echo, addr, certFile, keyFile, caFile string) (*Server, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("control: read CA cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("control: parse CA cert")
	}

	return &Server{
		certFile: certFile,
		keyFile:  keyFile,
		srv: &http.Server{
			Addr:    addr,
			Handler: e,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  caPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}, nil
}

func (s *Server) Start() error {
	return s.srv.ListenAndServeTLS(s.certFile, s.keyFile)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
