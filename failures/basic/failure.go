package basic

import (
	"net/http"

	"github.com/freman/caddy2-reauth/failures"
)

type Basic struct {
	Realm string `json:"realm,omitempty"`
}

// FailureMode name
const FailureMode = "httpbasic"

// Interface guard
var _ failures.Driver = (*Basic)(nil)

// NewDriver returns an instance of Basic
func NewDriver() *Basic {
	return &Basic{}
}

// Validate verifies that this module is functional with the given configuration
func (h Basic) Validate() error {
	return nil
}

// Handle the failure
func (h Basic) Handle(w http.ResponseWriter, r *http.Request) error {
	realm := r.Host

	if h.Realm != "" {
		realm = h.Realm
	}

	w.Header().Add("WWW-Authenticate", `Basic realm="`+realm+`"`)
	w.WriteHeader(http.StatusUnauthorized)

	return nil
}
