package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

const (
	APIBaseURL        = "https://api.osv.dev"
	EcosystemsListURL = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"
	RateLimit         = 10.0 // requests per second
	MaxConcurrency    = 5
	BatchSize         = 100
	HTTPTimeout       = 30 * time.Second

	defaultDBPath        = "./osv.db"
	defaultRetentionDays = 7
)

// Config holds application configuration loaded from environment variables.
type Config struct {
	DBPath        string
	Ecosystems    []model.Ecosystem
	RetentionDays int
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("load .env: %w", err)
	}

	ecosystems := model.ParseEcosystems(os.Getenv("OSV_ECOSYSTEMS"))

	retentionDays, err := getEnvInt("OSV_DATA_RETENTION_DAYS", defaultRetentionDays)
	if err != nil {
		return nil, fmt.Errorf("parse OSV_DATA_RETENTION_DAYS: %w", err)
	}

	return &Config{
		DBPath:        getEnv("OSV_DB_PATH", defaultDBPath),
		Ecosystems:    ecosystems,
		RetentionDays: retentionDays,
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) (int, error) {
	str := os.Getenv(key)
	if str == "" {
		return defaultValue, nil
	}
	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q: %w", str, err)
	}
	if val <= 0 {
		return 0, fmt.Errorf("value must be positive, got %d", val)
	}
	return val, nil
}
