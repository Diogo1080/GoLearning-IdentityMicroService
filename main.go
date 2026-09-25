package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/config"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/observability"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/service"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/tokens"
	server "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := godotenv.Load("./.env"); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	db, err := store.Connect(cfg.DatabaseURL())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := store.RunMigrations(db); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}

	rds := store.NewRedis(cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Password)
	defer rds.Client.Close()

	redisCtx, redisCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer redisCancel()
	if err := rds.Client.Ping(redisCtx).Err(); err != nil {
		log.Fatalf("failed to ping redis: %v", err)
	}

	identityRepo := store.NewSQLiteIdentityRepository(db)

	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	appLog := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(appLog)
	shutdownTracing, err := observability.SetupTracing(context.Background(), version)
	if err != nil {
		log.Fatalf("failed to configure tracing: %v", err)
	}
	defer func() {
		if err := shutdownTracing(context.Background()); err != nil {
			appLog.Error("failed to shut down tracing", "err", err)
		}
	}()

	metrics := observability.NewMetrics(prometheus.DefaultRegisterer)
	prometheus.MustRegister(observability.BuildInfo(version, commit, buildDate))

	grpcServer := grpc.NewServer(
		grpc.StatsHandler(observability.GRPCStatsHandler()),
		grpc.ChainUnaryInterceptor(metrics.UnaryServerInterceptor),
		grpc.ChainStreamInterceptor(metrics.StreamServerInterceptor),
	)

	reflection.Register(grpcServer)

	tokenManager, err := tokens.NewTokenManager(rds, cfg.Tokens.AccessSecret, cfg.Tokens.RefreshSecret)
	if err != nil {
		log.Fatalf("Invalid token configuration: %v", err)
	}

	iIdentityService := service.NewInternalIdentityService(identityRepo, tokenManager)

	authv1.RegisterInternalIdentityServiceServer(grpcServer, iIdentityService)

	r := gin.Default()
	r.Use(metrics.GinMiddleware)
	r.GET("/metrics", metrics.Handler())

	// Build auth middleware
	identityMiddleware := middleware.NewidentityMiddlewareBuilder(iIdentityService).Build()

	// Initialize services (web service layer - no auth logic)
	pIdentiyService := service.NewPublicIdentityService(identityRepo, tokenManager)

	//Build the handler
	identityHandler := server.NewIdentityHandler(pIdentiyService, tokenManager)

	//Register routes with auth middleware
	server.RegisterRoutes(r, identityHandler, identityMiddleware, server.Readiness(db, rds.Client))

	grpcAddress := fmt.Sprintf(":%s", cfg.GRPCPort)
	httpAddress := fmt.Sprintf(":%s", cfg.AppPort)
	httpServer := &http.Server{
		Addr:              httpAddress,
		Handler:           otelhttp.NewHandler(r, "identity-http"),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	appLog.Info("auth gRPC server listening", "port", grpcAddress)
	appLog.Info("auth HTTP server listening", "port", httpAddress)

	serverErrors := make(chan error, 2)
	go func() {
		serverErrors <- grpcServer.Serve(lis)
	}()
	go func() {
		serverErrors <- httpServer.ListenAndServe()
	}()
	var pprofServer *http.Server
	if os.Getenv("PPROF_ENABLED") == "true" {
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofPort := os.Getenv("PPROF_PORT")
		if pprofPort == "" {
			pprofPort = "6060"
		}
		pprofServer = &http.Server{Addr: "127.0.0.1:" + pprofPort, Handler: pprofMux, ReadHeaderTimeout: 5 * time.Second}
		go func() { serverErrors <- pprofServer.ListenAndServe() }()
		appLog.Warn("pprof enabled on localhost", "address", pprofServer.Addr)
	}

	shutdownSignal, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()

	select {
	case <-shutdownSignal.Done():
		appLog.Info("shutdown signal received")
	case err := <-serverErrors:
		if err != nil && err != grpc.ErrServerStopped && err != http.ErrServerClosed {
			appLog.Error("server stopped unexpectedly", "err", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		appLog.Error("failed to shut down HTTP server gracefully", "err", err)
	}
	if pprofServer != nil {
		if err := pprofServer.Shutdown(shutdownCtx); err != nil {
			appLog.Error("failed to shut down pprof server gracefully", "err", err)
		}
	}

	grpcStopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(grpcStopped)
	}()
	select {
	case <-grpcStopped:
	case <-shutdownCtx.Done():
		appLog.Warn("gRPC graceful shutdown timed out; forcing stop")
		grpcServer.Stop()
	}
}
