package reauth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/freman/caddy2-reauth/failures"
	"github.com/freman/caddy2-reauth/failures/basic"
	"github.com/freman/caddy2-reauth/failures/redirect"
	"github.com/freman/caddy2-reauth/failures/status"
)

// Failure is a failure mode
type Failure struct {
	Mode   string `json:"mode,omitempty"`
	driver failures.Driver
}

// Handle handles the failure mode.
func (f *Failure) Handle(w http.ResponseWriter, r *http.Request) error {
	return f.driver.Handle(w, r)
}

// Validate checks whether an failure mode is functional.
func (f *Failure) Validate() error {
	if f.driver == nil {
		f.Mode = status.FailureMode
		f.driver = status.NewDriver()
	}
	return f.driver.Validate()
}

// MarshalJSON packs configuration info JSON byte array
func (f Failure) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.driver)
}

// UnmarshalJSON unpacks configuration into appropriate structures.
func (f *Failure) UnmarshalJSON(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("invalid configuration: %s", data)
	}

	type undecorated Failure
	var failure undecorated

	if err := json.Unmarshal(data, &failure); err != nil {
		return fmt.Errorf("invalid reauth configuration, error: %s, config: %s", err, data)
	}

	var driver failures.Driver
	switch failure.Mode {
	case basic.FailureMode:
		driver = basic.NewDriver()
	case redirect.FailureMode:
		driver = redirect.NewDriver()
	case status.FailureMode:
		driver = status.NewDriver()
	default:
		return fmt.Errorf("invalid reauth configuration, error: unknown failure mode %q, config: %s", failure.Mode, data)
	}

	if err := json.Unmarshal(data, driver); err != nil {
		return fmt.Errorf("invalid reauth:%s configuration, error: %s, config:%s", failure.Mode, err, data)
	}

	if err := driver.Validate(); err != nil {
		return fmt.Errorf("invalid reauth:%s configuration, error: %s, config: %s", failure.Mode, err, data)
	}

	f.Mode = failure.Mode
	f.driver = driver
	return nil
}
