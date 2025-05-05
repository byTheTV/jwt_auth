package handlers

import (
	"auth-service/storage"
	"auth-service/token"
	"log"
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

	ip := c.ClientIP()

	accessToken, jti, err := token.GenerateAccessToken(userID, ip, h.secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}

	refreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	if err := h.db.SaveRefreshToken(userID, jti, refreshToken, ip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func (h *AuthHandler) RefreshTokens(c *gin.Context) {
	accessTokenString := c.GetHeader("Authorization")
	if accessTokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing access token"})
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	claims, err := token.ParseAccessToken(accessTokenString, h.secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
		return
	}

	storedToken, err := h.db.FindRefreshToken(claims.ID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if storedToken.Used {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token already used"})
		return
	}

	if err := token.CompareRefreshToken(storedToken.RefreshTokenHash, req.RefreshToken); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	currentIP := c.ClientIP()
	if storedToken.IP != currentIP {
		sendWarningEmail(claims.UserID, currentIP)
	}

	newAccessToken, newJTI, err := token.GenerateAccessToken(claims.UserID, currentIP, h.secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new access token"})
		return
	}

	newRefreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate new refresh token"})
		return
	}

	if err := h.db.UpdateRefreshTokens(storedToken.ID, newJTI, newRefreshToken, currentIP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

func sendWarningEmail(userID, newIP string) {
	// Mock email sending
	log.Printf("Warning: IP changed for user %s. New IP: %s", userID, newIP)
}
