package handlers

import (
	"auth-service/storage"
)

type AuthHandler struct {
	db     storage.Storage
	secret string
}
