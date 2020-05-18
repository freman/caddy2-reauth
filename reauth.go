package reauth

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Reauth{})
}

// Reauth module
type Reauth struct {
	Backends []Backend `json:"backends,omitempty"`
	Failure  Failure   `json:"failure,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Reauth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.reauth",
		New: func() caddy.Module { return new(Reauth) },
	}
}

// Provision implements caddy.Provisioner.
func (r *Reauth) Provision(ctx caddy.Context) error {
	r.logger = ctx.Logger(r)
	r.logger.Info("provisioning plugin instance")
	return nil
}

// Validate implements caddy.Validator.
func (r Reauth) Validate() error {
	for i, be := range r.Backends {
		if err := be.Validate(); err != nil {
			return fmt.Errorf("backends[%d] (%s) failed validation: %s", i, be.Type, err)
		}
	}

	if err := r.Failure.Validate(); err != nil {
		return fmt.Errorf("failure mode %s failed validation: %s", r.Failure.Mode, err)
	}

	return nil
}

// Authenticate the request
func (r Reauth) Authenticate(w http.ResponseWriter, req *http.Request) (caddyauth.User, bool, error) {
	for _, b := range r.Backends {
		user, err := b.Authenticate(req)
		if err != nil {
			return caddyauth.User{}, false, err
		}
		if user != "" {
			return caddyauth.User{
				ID: user,
				Metadata: map[string]string{
					"reauth_backend": b.Type,
				},
			}, true, nil
		}
	}

	return caddyauth.User{}, false, r.Failure.Handle(w, req)
}

// Interface guards
var (
	_ caddy.Provisioner       = (*Reauth)(nil)
	_ caddy.Validator         = (*Reauth)(nil)
	_ caddyauth.Authenticator = (*Reauth)(nil)
)
