package main

import (
	"auth-service/config"
	"auth-service/handlers"
	"auth-service/storage"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	db, err := storage.NewPostgresDB(cfg.Postgres)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	router := gin.Default()
	authHandler := handlers.NewAuthHandler(db, cfg.JWT.Secret)
	
	router.GET("/auth/token", authHandler.IssueTokens)
	router.POST("/auth/refresh", authHandler.RefreshTokens)
	
	log.Fatal(router.Run(":" + cfg.Server.Port))
}
