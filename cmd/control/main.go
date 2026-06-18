package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ramadhantriyant/gonac/config"
	"github.com/ramadhantriyant/gonac/internal/control"
	"github.com/ramadhantriyant/gonac/internal/router"
	"github.com/ramadhantriyant/gonac/internal/store"
)

func main() {
	configPath := "config-control.yaml"
	if p := os.Getenv("GONAC_CONFIG"); p != "" {
		configPath = p
	}

	cfg, err := config.LoadControl(configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	// Agent server: mTLS on cfg.ListenAddress
	agentEcho := router.NewRouter(st)
	agentSrv, err := control.New(agentEcho, cfg.ListenAddress, cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CAFile)
	if err != nil {
		log.Fatalf("agent server: %v", err)
	}

	// Admin server: plain HTTP on cfg.AdminAddress
	adminSrv := &http.Server{
		Addr:    cfg.AdminAddress,
		Handler: router.NewAdminRouter(st, cfg.AdminToken),
	}

	go func() {
		log.Printf("gonac-control: admin listening on %s (HTTP)", cfg.AdminAddress)
		if err := adminSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("admin serve: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		adminSrv.Shutdown(context.Background())
		agentSrv.Shutdown(context.Background())
	}()

	log.Printf("gonac-control: agent listening on %s (mTLS)", cfg.ListenAddress)
	if err := agentSrv.Start(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	log.Println("gonac-control: stopped")
}
