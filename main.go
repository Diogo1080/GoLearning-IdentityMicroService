package main

import (
	authv1 "GoLearning-IdentityMicroService/api/v1"
	"GoLearning-IdentityMicroService/internal/service"
	"GoLearning-IdentityMicroService/internal/store"
	server "GoLearning-IdentityMicroService/internal/transport/http"
	middleware "GoLearning-IdentityMicroService/internal/transport/http/middleware"
	"log"
	"net"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	if err := godotenv.Load("../../.env"); err != nil {
		log.Println(err.Error())
	}

	db, err := store.Connect(store.GetConnectionURL())
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	rds := store.NewRedis()
	defer rds.Client.Close()

	identityRepo := store.NewSQLiteIdentityRepository(db)
	//userRepo := store.NewSQLiteUserRepository(db)

	lis, err := net.Listen("tcp", ":"+os.Getenv("AUTH_PORT"))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()

	reflection.Register(grpcServer)

	iIdentityService := service.NewInternalIdentityService(identityRepo, rds)

	authv1.RegisterInternalIdentityServiceServer(grpcServer, iIdentityService)

	r := gin.Default()

	// Build auth middleware (uses gRPC validation)
	identityMiddleware := middleware.NewidentityMiddlewareBuilder(iIdentityService).Build()

	// Initialize services (web service layer - no auth logic)
	pIdentiyService := service.NewPublicIdentityService(identityRepo, rds)

	identityHandler := server.NewIdentityHandler(pIdentiyService)

	//Register routes with auth middleware
	server.RegisterRoutes(r, identityHandler, identityMiddleware)

	log.Printf("Auth gRPC server listening on port %s", os.Getenv("AUTH_PORT"))
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
