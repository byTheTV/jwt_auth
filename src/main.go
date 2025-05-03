package main

import (
	"auth-service/config"
	"log"
)

func main() {
	_, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

}
