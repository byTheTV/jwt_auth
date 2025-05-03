package storage

import (
	"auth-service/config"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	SaveRefreshToken(userID, jti, refreshToken string) error
	FindRefreshToken(jti string) (*RefreshToken, error)
	UpdateRefreshTokens(oldJTI, newJTI, newRefreshToken string) error
}

type PostgresDB struct {
	db *sql.DB
}

type RefreshToken struct {
	ID               string
	UserID           string
	AccessTokenJTI   string
	RefreshTokenHash string
	CreatedAt        time.Time
	ExpiresAT        time.Time
	Used             bool
}

func NewPostgresDB(cfg config.PostgresConfig) (*PostgresDB, error) {
	connStr := fmt.Sprintf("host=%s, port=%s, user=%s, password=%s, dbname=%s", cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresDB{db: db}, nil
}

func (p *PostgresDB) SaveRefreshToken(userID, jti, refreshToken string) error {
	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = p.db.Exec(
		"INSERT INTO refresh_tokens (user_id, access_token_jti, refresh_token_hash, expires_at) VALUES ($1, $2, $3, $4)",
		userID, jti, string(hashedRefresh), time.Now().Add(7*24*time.Hour),
	)
	return err
}

func (p *PostgresDB) FindRefreshToken(jti string) (*RefreshToken, error) {
	var token RefreshToken

	row := p.db.QueryRow(
		"SELECT id, user_id, access_token_jti, refresh_token_hash, created_at, expires_at, used "+
			"FROM refresh_tokens "+
			"WHERE access_token_jti = $1 AND used = false AND expires_at > NOW()",
		jti,
	)

	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.AccessTokenJTI,
		&token.RefreshTokenHash,
		&token.CreatedAt,
		&token.ExpiresAT,
		&token.Used,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("token not found")
		}
		return nil, err
	}
	return &token, nil
}

func (p *PostgresDB) UpdateRefreshTokens(oldJTI, newJTI, newRefreshToken string) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}

	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(newRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		tx.Rollback()
		return err
	}

	// Пометка о использовании старого токена
	_, err = tx.Exec(
		"UPDATE refresh_tokens SET used = true WHERE access_token_jti = $1",
		oldJTI,
	)
	if err != nil {
		tx.Rollback()
		return err
	}

	// insert new one
	_, err = tx.Exec(
		"INSERT INTO refresh_tokens (user_id, access_token_jti, refresh_token_hash, expires_at) "+
			"VALUES ((SELECT user_id FROM refresh_tokens WHERE access_token_jti = $1), $2, $3, $4)",
		oldJTI, newJTI, string(hashedRefresh), time.Now().Add(7*24*time.Hour),
	)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
