package handlers

import (
	"auth-service/storage"
	"auth-service/token"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	db     storage.Storage
	secret string
}

func NewAuthHandler(db storage.Storage, secret string) *AuthHandler {
	return &AuthHandler{db: db, secret: secret}
}

func (h *AuthHandler) IssueTokens(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	accessToken, jti, err := token.GenerateAccessToken(userID, h.secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate accessTOken"})
		return
	}

	refreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refreshToken"})
		return
	}

	if err := h.db.SaveRefreshToken(userID, jti, refreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refreshTOken"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
