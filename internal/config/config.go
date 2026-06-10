package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"github.com/joho/godotenv"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

const (
	// EcosystemsListURL is the canonical OSV ecosystem allowlist source.
	// Used at startup to validate OSV_ECOSYSTEMS against the upstream
	// catalog before any download begins.
	EcosystemsListURL = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"

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
