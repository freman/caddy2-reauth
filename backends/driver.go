package backends

import (
	"net/http"
)

// Driver is an interface to an authentication provider.
type Driver interface {
	Authenticate(r *http.Request) (string, error)
	Validate() error
}
