// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
// Package config provides configuration management for the transparenz-server application.
// It uses Viper to load configuration from environment variables and .env files,
// with support for default values and validation.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration values for the application.
// Configuration is loaded from environment variables and .env files,
// with support for default values.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string
	DatabaseURL string `mapstructure:"DATABASE_URL"`
	// BaseURL is the public base URL of this server (used for CSAF provider metadata canonical URLs)
	BaseURL string `mapstructure:"BASE_URL"`

	// JWTSecret is the secret key used for JWT token signing and validation
	JWTSecret string `mapstructure:"JWT_SECRET"`

	// EncryptionKey is the AES-256 key used to encrypt sensitive data at rest
	EncryptionKey string `mapstructure:"ENCRYPTION_KEY"`

	// Port is the HTTP server port
	Port string `mapstructure:"PORT"`

	// LogLevel controls the logging verbosity (debug, info, warn, error)
	LogLevel string `mapstructure:"LOG_LEVEL"`

	// MaxSBOMSize is the maximum SBOM document size in bytes (default 10MB)
	MaxSBOMSize int `mapstructure:"MAX_SBOM_SIZE"`

	// MultiTenantMode controls tenant isolation strategy: "shared", "schema_per_org", "instance_per_org"
	MultiTenantMode string `mapstructure:"MULTI_TENANT_MODE"`

	// InstanceDSNs maps org IDs to their dedicated database connection strings (JSON string)
	InstanceDSNs map[string]string `mapstructure:"INSTANCE_DSNS"`

	// VulnzWorkspacePath is the path to the vulnz workspace directory
	VulnzWorkspacePath string `mapstructure:"VULNZ_WORKSPACE_PATH"`

	// VulnzSyncInterval is the interval between vulnz feed syncs
	VulnzSyncInterval time.Duration `mapstructure:"VULNZ_SYNC_INTERVAL"`

	ENISATimeout            time.Duration `mapstructure:"ENISA_TIMEOUT"`
	AlertTickInterval       time.Duration `mapstructure:"ALERT_TICK_INTERVAL"`
	SLATickInterval         time.Duration `mapstructure:"SLA_TICK_INTERVAL"`
	ApproachingSLAThreshold time.Duration `mapstructure:"APPROACHING_SLA_THRESHOLD"`
	ENISARetryInterval      time.Duration `mapstructure:"ENISA_RETRY_INTERVAL"`
	ENISAMaxRetries         int           `mapstructure:"ENISA_MAX_RETRIES"`
	JobQueuePollInterval    time.Duration `mapstructure:"JOB_QUEUE_POLL_INTERVAL"`

	CORSAllowedOrigins []string `mapstructure:"CORS_ALLOWED_ORIGINS"`
	MetricsUser        string   `mapstructure:"METRICS_USER"`
	MetricsPassword    string   `mapstructure:"METRICS_PASSWORD"`

	GreenboneEnabled   bool `mapstructure:"GREENBONE_ENABLED"`
	SbomWebhookEnabled bool `mapstructure:"SBOM_WEBHOOK_ENABLED"`
	TelemetryEnabled   bool `mapstructure:"TELEMETRY_ENABLED"`
	VulnzDisabled      bool `mapstructure:"VULNZ_DISABLED"`
	RateLimitDisabled  bool `mapstructure:"RATE_LIMIT_DISABLED"`

	EnrichmentDBPath   string `mapstructure:"ENRICHMENT_DB_PATH"`
	EnrichmentAutoInit bool   `mapstructure:"ENRICHMENT_AUTO_INIT"`
}

// LoadConfig loads configuration from environment variables and .env file.
// It sets default values for PORT and LOG_LEVEL, validates required fields,
// and returns a populated Config struct.
//
// Configuration is loaded in the following order (later sources override earlier):
//  1. Default values
//  2. .env file (if it exists)
//  3. Environment variables
//
// Returns an error if:
//   - DATABASE_URL is not set
//   - JWT_SECRET is not set
//   - JWT_SECRET is less than 32 characters (256-bit key requirement)
func LoadConfig() (*Config, error) {
	// Set default values
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("MAX_SBOM_SIZE", 10*1024*1024)
	viper.SetDefault("MULTI_TENANT_MODE", "shared")
	viper.SetDefault("VULNZ_WORKSPACE_PATH", "/var/lib/vulnz/workspace")
	viper.SetDefault("VULNZ_SYNC_INTERVAL", "6h")
	viper.SetDefault("ENISA_TIMEOUT", "30s")
	viper.SetDefault("ALERT_TICK_INTERVAL", "30s")
	viper.SetDefault("SLA_TICK_INTERVAL", "1m")
	viper.SetDefault("APPROACHING_SLA_THRESHOLD", "6h")
	viper.SetDefault("ENISA_RETRY_INTERVAL", "15m")
	viper.SetDefault("ENISA_MAX_RETRIES", 5)
	viper.SetDefault("JOB_QUEUE_POLL_INTERVAL", "5s")
	viper.SetDefault("GREENBONE_ENABLED", false)
	viper.SetDefault("SBOM_WEBHOOK_ENABLED", false)
	viper.SetDefault("TELEMETRY_ENABLED", true)
	viper.SetDefault("VULNZ_DISABLED", false)
	viper.SetDefault("RATE_LIMIT_DISABLED", false)
	viper.SetDefault("ENRICHMENT_DB_PATH", "/var/lib/enrichment/enrichment.db")
	viper.SetDefault("ENRICHMENT_AUTO_INIT", true)

	// Load from .env file if it exists (don't error if it doesn't)
	viper.SetConfigFile(".env")
	if err := viper.ReadInConfig(); err != nil {
		// Only ignore "file not found" errors, return other errors
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// .env file doesn't exist, which is fine - we'll use env vars
	}

	// Allow environment variables to override .env file
	viper.AutomaticEnv()

	// Unmarshal configuration into Config struct
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if raw := viper.GetString("CORS_ALLOWED_ORIGINS"); raw != "" {
		config.CORSAllowedOrigins = strings.Split(raw, ",")
	}
	if len(config.CORSAllowedOrigins) == 0 {
		config.CORSAllowedOrigins = []string{"http://localhost:8080"}
	}

	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// validateConfig validates the configuration values.
// Returns an error if any required fields are missing or invalid.
func validateConfig(config *Config) error {
	// Validate DATABASE_URL
	if config.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required but not set")
	}

	// Validate JWT_SECRET exists
	if config.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required but not set")
	}

	// Validate JWT_SECRET length (minimum 32 characters for 256-bit security)
	if len(config.JWTSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters long (current length: %d)", len(config.JWTSecret))
	}

	// Validate ENCRYPTION_KEY exists
	if config.EncryptionKey == "" {
		return fmt.Errorf("ENCRYPTION_KEY is required but not set")
	}

	// Validate ENCRYPTION_KEY length (must be exactly 32 characters for AES-256)
	if len(config.EncryptionKey) != 32 {
		return fmt.Errorf("ENCRYPTION_KEY must be exactly 32 characters long (current length: %d)", len(config.EncryptionKey))
	}

	return nil
}
