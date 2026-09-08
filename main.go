package main

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	"GoLearning-IdentityMicroService/internal/logger"
	"GoLearning-IdentityMicroService/internal/service"
	"GoLearning-IdentityMicroService/internal/store"
	tokens "GoLearning-IdentityMicroService/internal/tokens"
	server "GoLearning-IdentityMicroService/internal/transport/http"
	middleware "GoLearning-IdentityMicroService/internal/transport/http/middleware"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

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

	lis, err := net.Listen("tcp", ":"+os.Getenv("PORT"))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log := logger.New()

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

	log.Info("Auth gRPC server listening on %s", grpcAddress)
	log.Info("Auth HTTP server listening on %s", httpAddress)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Error("Failed to serve gRPC: %v", err)
		}
	}()

	if err := http.ListenAndServe(httpAddress, r); err != nil {
		log.Error("Failed to serve HTTP: %v", err)
	}

	//Kubernets will require signal handling
	//Look for Error Group to help  https://pkg.go.dev/golang.org/x/sync/errgroup
}
