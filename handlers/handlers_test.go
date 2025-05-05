package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-service/storage"
	"auth-service/token"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// MockStorage - мок для интерфейса Storage
type MockStorage struct {
	refreshTokens map[string]*storage.RefreshToken
}

func (m *MockStorage) SaveRefreshToken(userID, jti, refreshToken, ip string) error {
	hashedRefresh, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	m.refreshTokens[jti] = &storage.RefreshToken{
		ID:               "test-id",
		UserID:           userID,
		AccessTokenJTI:   jti,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		CreatedAt:        time.Now(),
		ExpiresAT:        time.Now().Add(7 * 24 * time.Hour),
		Used:             false,
	}
	return nil
}

func (m *MockStorage) FindRefreshToken(jti string) (*storage.RefreshToken, error) {
	if token, exists := m.refreshTokens[jti]; exists {
		return token, nil
	}
	return nil, sql.ErrNoRows
}

func (m *MockStorage) UpdateRefreshTokens(oldJTI, newJTI, newRefreshToken, ip string) error {
	if _, exists := m.refreshTokens[oldJTI]; !exists {
		return fmt.Errorf("no refresh token found")
	}
	hashedRefresh, _ := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	m.refreshTokens[oldJTI].Used = true
	m.refreshTokens[newJTI] = &storage.RefreshToken{
		ID:               "new-test-id",
		UserID:           m.refreshTokens[oldJTI].UserID,
		AccessTokenJTI:   newJTI,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		CreatedAt:        time.Now(),
		ExpiresAT:        time.Now().Add(7 * 24 * time.Hour),
		Used:             false,
	}
	return nil
}

func setupRouter(db storage.Storage, secret string) *gin.Engine {
	router := gin.Default()
	authHandler := NewAuthHandler(db, secret)
	router.GET("/auth/token", authHandler.IssueTokens)
	router.POST("/auth/refresh", authHandler.RefreshTokens)
	return router
}

func TestIssueTokens(t *testing.T) {
	mockStorage := &MockStorage{refreshTokens: make(map[string]*storage.RefreshToken)}
	secret := "test-secret"
	router := setupRouter(mockStorage, secret)

	t.Run("Successful token issuance", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/auth/token?user_id=550e8400-e29b-41d4-a716-446655440000", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["access_token"] == "" || response["refresh_token"] == "" {
			t.Error("Expected access_token and refresh_token in response")
		}
	})

	t.Run("Missing user_id", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/auth/token", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", w.Code)
		}

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["error"] != "user_id is required" {
			t.Errorf("Expected error 'user_id is required', got %s", response["error"])
		}
	})
}

func TestRefreshTokens(t *testing.T) {
	secret := "test-secret"

	t.Run("Successful_token_refresh", func(t *testing.T) {
		mockStorage := &MockStorage{refreshTokens: make(map[string]*storage.RefreshToken)}
		userID := "550e8400-e29b-41d4-a716-446655440000"
		ip := "127.0.0.1"
		accessToken, jti, _ := token.GenerateAccessToken(userID, ip, secret)
		refreshToken, _ := token.GenerateRefreshToken()
		mockStorage.SaveRefreshToken(userID, jti, refreshToken, ip)

		body := map[string]string{"refresh_token": refreshToken}
		bodyBytes, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:12345"

		w := httptest.NewRecorder()
		router := setupRouter(mockStorage, secret)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["access_token"] == "" || response["refresh_token"] == "" {
			t.Error("Expected new access_token and refresh_token in response")
		}
	})

	t.Run("Missing_Authorization_header", func(t *testing.T) {
		mockStorage := &MockStorage{refreshTokens: make(map[string]*storage.RefreshToken)}
		userID := "550e8400-e29b-41d4-a716-446655440000"
		ip := "127.0.0.1"
		_, jti, _ := token.GenerateAccessToken(userID, ip, secret)
		refreshToken, _ := token.GenerateRefreshToken()
		mockStorage.SaveRefreshToken(userID, jti, refreshToken, ip)

		body := map[string]string{"refresh_token": refreshToken}
		bodyBytes, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:12345"

		w := httptest.NewRecorder()
		router := setupRouter(mockStorage, secret)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["error"] != "missing access token" {
			t.Errorf("Expected error 'missing access token', got %s", response["error"])
		}
	})

	t.Run("Invalid_Authorization_header_format", func(t *testing.T) {
		mockStorage := &MockStorage{refreshTokens: make(map[string]*storage.RefreshToken)}
		userID := "550e8400-e29b-41d4-a716-446655440000"
		ip := "127.0.0.1"
		accessToken, jti, _ := token.GenerateAccessToken(userID, ip, secret)
		refreshToken, _ := token.GenerateRefreshToken()
		mockStorage.SaveRefreshToken(userID, jti, refreshToken, ip)

		body := map[string]string{"refresh_token": refreshToken}
		bodyBytes, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", accessToken) // Без префикса Bearer
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:12345"

		w := httptest.NewRecorder()
		router := setupRouter(mockStorage, secret)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["error"] != "invalid authorization header" {
			t.Errorf("Expected error 'invalid authorization header', got %s", response["error"])
		}
	})

	t.Run("Invalid_refresh_token", func(t *testing.T) {
		mockStorage := &MockStorage{refreshTokens: make(map[string]*storage.RefreshToken)}
		userID := "550e8400-e29b-41d4-a716-446655440000"
		ip := "127.0.0.1"
		accessToken, jti, _ := token.GenerateAccessToken(userID, ip, secret)
		// Не сохраняем refresh_token в mockStorage, чтобы симулировать невалидный токен
		mockStorage.SaveRefreshToken(userID, jti, "valid-hash-but-not-used", ip)

		body := map[string]string{"refresh_token": "invalid-token"}
		bodyBytes, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:12345"

		w := httptest.NewRecorder()
		router := setupRouter(mockStorage, secret)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["error"] != "invalid refresh token" {
			t.Errorf("Expected error 'invalid refresh token', got %s", response["error"])
		}
	})

	t.Run("IP_mismatch_warning", func(t *testing.T) {
		mockStorage := &MockStorage{refreshTokens: make(map[string]*storage.RefreshToken)}
		userID := "550e8400-e29b-41d4-a716-446655440000"
		ip := "127.0.0.1"
		accessToken, jti, _ := token.GenerateAccessToken(userID, ip, secret)
		refreshToken, _ := token.GenerateRefreshToken()
		mockStorage.SaveRefreshToken(userID, jti, refreshToken, ip)

		body := map[string]string{"refresh_token": refreshToken}
		bodyBytes, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.168.1.1:12345" // Different IP

		w := httptest.NewRecorder()
		router := setupRouter(mockStorage, secret)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		if response["access_token"] == "" || response["refresh_token"] == "" {
			t.Error("Expected new access_token and refresh_token in response")
		}
	})
}
