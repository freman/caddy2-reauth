package redirect

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/freman/caddy2-reauth/failures"
	"github.com/freman/caddy2-reauth/jsontypes"
)

// FailureMode name
const FailureMode = "redirect"

const defaultRedirectCode = 303

// Interface guard
var _ failures.Driver = (*Redirect)(nil)

type Redirect struct {
	URL  *jsontypes.URL `json:"url,omitempty"`
	Code int            `json:"code,omitempty"`
}

// NewDriver returns a new instance of Redirect
func NewDriver() *Redirect {
	return &Redirect{
		Code: defaultRedirectCode,
	}
}

// Validate verifies that this module is functional with the given configuration
func (h Redirect) Validate() error {
	if h.URL == nil {
		return errors.New("url to redirect to is a required parameter")
	}

	return nil
}

// Handle the error
func (h Redirect) Handle(w http.ResponseWriter, r *http.Request) error {
	uri := r.URL
	uri.Host = ""
	uri.Scheme = ""

	// Handle redirection back to hosts that aren't the auth server.
	if h.URL.Host != "" && h.URL.Host != r.Host {
		uri.Host = r.Host
		uri.Scheme = "http"
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			uri.Scheme = "https"
		}
	}

	redirect := strings.Replace(h.URL.String(), "{uri}", url.QueryEscape(uri.String()), -1)
	w.Header().Add("Location", redirect)
	http.Redirect(w, r, redirect, h.Code)

	return nil
}
