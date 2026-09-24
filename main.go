package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"

	authv1 "github.com/Diogo1080/GoLearning-IdentityMicroService/api/v1"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/service"
	"github.com/Diogo1080/GoLearning-IdentityMicroService/internal/store"
	tokens "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/tokens"
	server "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http"
	middleware "github.com/Diogo1080/GoLearning-IdentityMicroService/internal/transport/http/middleware"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	if err := godotenv.Load("./.env"); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	db, err := store.Connect(store.GetConnectionURL())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	rds := store.NewRedis()
	defer rds.Client.Close()

	identityRepo := store.NewSQLiteIdentityRepository(db)

	lis, err := net.Listen("tcp", ":"+os.Getenv("GRPC_PORT"))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	appLog := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(appLog)

	grpcServer := grpc.NewServer()

	reflection.Register(grpcServer)

	tokenManager := tokens.NewTokenManager(rds)

	iIdentityService := service.NewInternalIdentityService(identityRepo, tokenManager)

	authv1.RegisterInternalIdentityServiceServer(grpcServer, iIdentityService)

	r := gin.Default()

	// Build auth middleware
	identityMiddleware := middleware.NewidentityMiddlewareBuilder(iIdentityService).Build()

	// Initialize services (web service layer - no auth logic)
	pIdentiyService := service.NewPublicIdentityService(identityRepo, tokenManager)

	//Build the handler
	identityHandler := server.NewIdentityHandler(pIdentiyService, tokenManager)

	//Register routes with auth middleware
	server.RegisterRoutes(r, identityHandler, identityMiddleware)

	grpcAddress := fmt.Sprintf(":%s", os.Getenv("GRPC_PORT"))
	httpAddress := fmt.Sprintf(":%s", os.Getenv("APP_PORT"))

	appLog.Info("auth gRPC server listening", "port", grpcAddress)
	appLog.Info("auth HTTP server listening", "port", httpAddress)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			appLog.Error("failed to serve gRPC", "err", err)
		}
	}()

	if err := http.ListenAndServe(httpAddress, r); err != nil {
		appLog.Error("failed to serve HTTP", "err", err)
	}

	//Kubernets will require signal handling
	//Look for Error Group to help  https://pkg.go.dev/golang.org/x/sync/errgroup
}
