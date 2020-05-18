package status

import (
	"net/http"

	"github.com/freman/caddy2-reauth/failures"
)

// FailureMode name
const FailureMode = "status"

const defaultCode = http.StatusForbidden

// Interface guard
var _ failures.Driver = (*Status)(nil)

// Status simply returns a http status code
type Status struct {
	Code int `json:"code,omitempty"`
}

// NewDriver returns an instance of Status with some configured defaults
func NewDriver() *Status {
	return &Status{
		Code: defaultCode,
	}
}

// Validate verifies that this module is functional with the given configuration
func (h Status) Validate() error {
	return nil
}

// Handle the failure
func (h Status) Handle(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(h.Code)
	return nil
}
