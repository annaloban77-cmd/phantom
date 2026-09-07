package common

import "time"

// ServerConfig holds server configuration
type ServerConfig struct {
	Listen        string            `yaml:"listen"`
	TLS           TLSConfig         `yaml:"tls"`
	MasqueradeSite string           `yaml:"masquerade_site"`
	RateLimit     int               `yaml:"rate_limit"`
	Auth          AuthConfig        `yaml:"auth"`
	Logging       LoggingConfig     `yaml:"logging"`
}

// TLSConfig holds TLS certificate configuration
type TLSConfig struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	PSKs []PSKUser `yaml:"psk"`
}

// PSKUser represents a pre-shared key user
type PSKUser struct {
	Key  string `yaml:"key"`
	Name string `yaml:"name"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// ClientConfig holds client configuration
type ClientConfig struct {
	Server   string            `yaml:"server"`
	PSK      string            `yaml:"psk"`
	Transport TransportConfig  `yaml:"transport"`
	Local     LocalConfig      `yaml:"local"`
	Evasion   EvasionConfig    `yaml:"evasion"`
	Behavior  BehaviorConfig   `yaml:"behavior"`
	Logging   LoggingConfig    `yaml:"logging"`
}

// TransportConfig holds transport mode configuration
type TransportConfig struct {
	Mode        string `yaml:"mode"`
	CFEndpoint  string `yaml:"cf_endpoint"`
	ProxyURL    string `yaml:"proxy_url"`
}

// LocalConfig holds local listener configuration
type LocalConfig struct {
	Socks5 string `yaml:"socks5"`
	Tun    string `yaml:"tun"`
}

// EvasionConfig holds evasion configuration
type EvasionConfig struct {
	Enable       bool     `yaml:"enable"`
	RetryDelayMs []int    `yaml:"retry_delay_ms"`
	MaxRetries   int      `yaml:"max_retries"`
	CertSPKIPin  string   `yaml:"cert_spki_pin"`
}

// BehaviorConfig holds traffic behavior configuration
type BehaviorConfig struct {
	IdlePolicy       IdlePolicyConfig       `yaml:"idle_policy"`
	SessionResumption SessionResumptionConfig `yaml:"session_resumption"`
	ConnectionReuse  ConnectionReuseConfig  `yaml:"connection_reuse"`
}

// IdlePolicyConfig holds idle traffic policy
type IdlePolicyConfig struct {
	Enabled        bool          `yaml:"enabled"`
	MinIdle        time.Duration `yaml:"min_idle"`
	MaxIdle        time.Duration `yaml:"max_idle"`
	BufferSize     int           `yaml:"buffer_size"`
	TriggerOnBytes int           `yaml:"trigger_on_bytes"`
}

// SessionResumptionConfig holds session resumption settings
type SessionResumptionConfig struct {
	Enabled          bool `yaml:"enabled"`
	CacheSize        int  `yaml:"cache_size"`
	ReuseProbability float64 `yaml:"reuse_probability"`
}

// ConnectionReuseConfig holds connection reuse settings
type ConnectionReuseConfig struct {
	MaxLifetime   time.Duration `yaml:"max_lifetime"`
	MaxRequests   int           `yaml:"max_requests"`
	CloseTimeout  time.Duration `yaml:"close_timeout"`
}
