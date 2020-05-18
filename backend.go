package reauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/freman/caddy2-reauth/backends"
	"github.com/freman/caddy2-reauth/backends/gitlabci"
	"github.com/freman/caddy2-reauth/backends/ldap"
	"github.com/freman/caddy2-reauth/backends/simple"
	"github.com/freman/caddy2-reauth/backends/upstream"
)

// Backend is an authentication backend.
type Backend struct {
	Type   string `json:"type,omitempty"`
	driver backends.Driver
}

// Authenticate performs authentication with an authentication provider.
func (b *Backend) Authenticate(r *http.Request) (string, error) {
	return b.driver.Authenticate(r)
}

// Validate checks whether an authentication provider is functional.
func (b *Backend) Validate() error {
	return b.driver.Validate()
}

// MarshalJSON packs configuration info JSON byte array
func (b Backend) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.driver)
}

// UnmarshalJSON unpacks configuration into appropriate structures.
func (b *Backend) UnmarshalJSON(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("invalid configuration: %s", data)
	}

	type undecorated Backend
	var backend undecorated

	if err := json.Unmarshal(data, &backend); err != nil {
		return fmt.Errorf("invalid reauth configuration, error: %s, config: %s", err, data)
	}

	var driver backends.Driver
	switch backend.Type {
	case gitlabci.BackendName:
		driver = gitlabci.NewDriver()
	case ldap.BackendName:
		driver = ldap.NewDriver()
	case simple.BackendName:
		driver = simple.NewDriver()
	case upstream.BackendName:
		driver = upstream.NewDriver()
	default:
		return fmt.Errorf("invalid reauth configuration, error: unknown backend %q, config: %s", backend.Type, data)
	}

	if err := json.Unmarshal(data, driver); err != nil {
		return fmt.Errorf("invalid reauth:%s configuration, error: %s, config:%s", backend.Type, err, data)
	}

	if err := driver.Validate(); err != nil {
		return fmt.Errorf("invalid reauth:%s configuration, error: %s, config: %s", backend.Type, err, data)
	}

	b.Type = backend.Type
	b.driver = driver

	return nil
}
