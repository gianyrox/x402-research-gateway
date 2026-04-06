package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// GatewayConfig is the top-level gateway configuration.
type GatewayConfig struct {
	Port             int           `yaml:"port"`
	RecipientAddress string        `yaml:"recipientAddress"`
	Network          string        `yaml:"network"`
	FacilitatorURL   string        `yaml:"facilitatorUrl"`
	DefaultPrice     string        `yaml:"defaultPrice"`
	Routes           []RouteConfig `yaml:"routes"`
}

// RouteConfig defines a single x402-protected research API route.
type RouteConfig struct {
	ID          string         `yaml:"id"`
	Path        string         `yaml:"path"`
	Method      string         `yaml:"method"`
	Description string         `yaml:"description"`
	MimeType    string         `yaml:"mimeType"`
	Price       string         `yaml:"price"`
	Upstream    UpstreamConfig `yaml:"upstream"`
	CacheTTL    int            `yaml:"cacheTtlSeconds"`
}

// UpstreamConfig defines how to proxy requests to an upstream API.
type UpstreamConfig struct {
	BaseURL      string            `yaml:"baseUrl"`
	Path         string            `yaml:"path"`
	PathTemplate string            `yaml:"pathTemplate"` // e.g., "/compound/name/{name}/JSON" — {param} substituted from query
	Method       string            `yaml:"method"`
	Headers      map[string]string `yaml:"headers"`
	QueryParams  map[string]string `yaml:"queryParams"`
	PassThrough  []string          `yaml:"passThrough"`
	Timeout      int               `yaml:"timeoutSeconds"`
}

// LoadFromFile loads gateway configuration from a YAML file, with env overrides.
func LoadFromFile(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Expand environment variables in YAML
	expanded := os.ExpandEnv(string(data))

	var cfg GatewayConfig
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	// Apply env overrides
	if v := os.Getenv("PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Port = port
		}
	}
	if v := os.Getenv("RECIPIENT_ADDRESS"); v != "" {
		cfg.RecipientAddress = v
	}
	if v := os.Getenv("NETWORK"); v != "" {
		cfg.Network = v
	}
	if v := os.Getenv("FACILITATOR_URL"); v != "" {
		cfg.FacilitatorURL = v
	}

	// Apply defaults
	if cfg.Port == 0 {
		cfg.Port = 8091
	}
	if cfg.Network == "" {
		cfg.Network = "base-sepolia"
	}
	if cfg.FacilitatorURL == "" {
		cfg.FacilitatorURL = "https://facilitator.x402.rs"
	}
	if cfg.DefaultPrice == "" {
		cfg.DefaultPrice = "0.001"
	}

	for i := range cfg.Routes {
		if cfg.Routes[i].Method == "" {
			cfg.Routes[i].Method = "GET"
		}
		if cfg.Routes[i].MimeType == "" {
			cfg.Routes[i].MimeType = "application/json"
		}
		if cfg.Routes[i].Price == "" {
			cfg.Routes[i].Price = cfg.DefaultPrice
		}
		if cfg.Routes[i].Upstream.Timeout == 0 {
			cfg.Routes[i].Upstream.Timeout = 15
		}
		if cfg.Routes[i].Upstream.Method == "" {
			cfg.Routes[i].Upstream.Method = cfg.Routes[i].Method
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checks that the configuration is valid.
func (c *GatewayConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}
	if c.RecipientAddress == "" {
		return fmt.Errorf("recipientAddress is required (set RECIPIENT_ADDRESS env or in YAML)")
	}
	if len(c.RecipientAddress) != 42 || c.RecipientAddress[:2] != "0x" {
		return fmt.Errorf("invalid recipient address: %s", c.RecipientAddress)
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("at least one route is required")
	}
	seen := make(map[string]bool)
	for i, r := range c.Routes {
		if r.Path == "" {
			return fmt.Errorf("route[%d]: path is required", i)
		}
		if r.Upstream.BaseURL == "" {
			return fmt.Errorf("route[%d] %s: upstream.baseUrl is required", i, r.Path)
		}
		key := r.Method + " " + r.Path
		if seen[key] {
			return fmt.Errorf("duplicate route: %s", key)
		}
		seen[key] = true
	}
	return nil
}

// CAIP2Network returns the CAIP-2 formatted network identifier.
func (c *GatewayConfig) CAIP2Network() string {
	switch c.Network {
	case "base":
		return "eip155:8453"
	case "base-sepolia":
		return "eip155:84532"
	default:
		return c.Network
	}
}
