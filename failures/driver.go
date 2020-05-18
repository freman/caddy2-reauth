package failures

import "net/http"

// Driver is an interface to an failure provider.
type Driver interface {
	Handle(w http.ResponseWriter, r *http.Request) error
	Validate() error
}
