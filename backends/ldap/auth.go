/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Tamás Gulácsi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/freman/caddy2-reauth/backends"
	"github.com/freman/caddy2-reauth/jsontypes"

	ldp "github.com/go-ldap/ldap/v3"
)

// Interface guard
var _ backends.Driver = (*LDAP)(nil)

// BackendName name
const BackendName = "ldap"

const defaultPoolSize = 10
const defaultTimeout = time.Minute
const defaultFilter = "(&(objectClass=user)(sAMAccountName=%s))"

// LDAP backend provides authentication against LDAP paths, for example for Microsoft AD.
type LDAP struct {
	URL                *jsontypes.URL     `json:"url,omitempty"`
	BaseDN             string             `json:"base_dn,omitempty"`
	FilterDN           string             `json:"filter_dn,omitempty"`
	PrincipalSuffix    string             `json:"principal_suffix,omitempty"`
	BindDN             string             `json:"bind_dn,omitempty"`
	BindPassword       string             `json:"bind_password,omitempty"`
	TLS                bool               `json:"tls,omitempty"`
	InsecureSkipVerify bool               `json:"insecure_skip_verify,omitempty"`
	Timeout            jsontypes.Duration `json:"timeout,omitempty"`
	ConnectionPoolSize int                `json:"connection_pool_size,omitempty"`

	pool chan ldp.Client
}

// NewDriver returns a LDAP instance with some defaults
func NewDriver() *LDAP {
	return &LDAP{
		Timeout:            jsontypes.Duration{Duration: defaultTimeout},
		ConnectionPoolSize: defaultPoolSize,
		FilterDN:           defaultFilter,
	}
}

// Validate that this module is ready to go
func (h *LDAP) Validate() error {
	var missing []string
	if h.URL == nil {
		missing = append(missing, "URL")
	}

	if h.BindDN == "" {
		missing = append(missing, "BindDN")
	}

	if h.BindPassword == "" {
		missing = append(missing, "BindPassword")
	}

	if h.BaseDN == "" {
		missing = append(missing, "BaseDN")
	}

	if n := len(missing); n > 0 {
		var s string
		if n > 1 {
			s = "s"
		}
		return errors.New("missing the following required parameter" + s + ": " + strings.Join(missing, ", "))
	}

	if h.Timeout.Duration <= 0 {
		return errors.New("timeout must be greater than 0")
	}

	if h.ConnectionPoolSize <= 0 {
		return errors.New("connection pool size must be greater than 0")
	}

	h.pool = make(chan ldp.Client, h.ConnectionPoolSize)

	c, err := h.getConnection()
	if err != nil {
		return err
	}
	h.stashConnection(c)

	return nil
}

// Authenticate fulfils the backend interface
func (h *LDAP) Authenticate(r *http.Request) (string, error) {
	un, pw, k := r.BasicAuth()
	if !k {
		return "", nil
	}

	c, err := h.getConnection()
	if err != nil {
		return "", err
	}
	defer h.stashConnection(c)

	// Search for the given username
	searchRequest := ldp.NewSearchRequest(
		h.BaseDN,
		ldp.ScopeWholeSubtree, ldp.NeverDerefAliases, 0, int(h.Timeout.Duration/time.Second), false,
		fmt.Sprintf(h.FilterDN, un+h.PrincipalSuffix),
		[]string{"dn"},
		nil,
	)

	sr, err := c.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("search under %q for %q: %v", h.BaseDN, fmt.Sprintf(h.FilterDN, un+h.PrincipalSuffix), err)
	}

	if len(sr.Entries) == 0 {
		return "", nil
	}

	if len(sr.Entries) > 1 {
		return "", errors.New("too many entries returned")
	}

	userDN := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = c.Bind(userDN, pw)
	if err != nil {
		if ldp.IsErrorWithCode(err, ldp.LDAPResultInvalidCredentials) {
			return "", nil
		}
		return "", fmt.Errorf("bind with %q: %v", userDN, err)
	}

	return userDN, nil
}

func (h *LDAP) getConnection() (ldp.Client, error) {
	var c ldp.Client
	select {
	case c = <-h.pool:
		if err := c.Bind(h.BindDN, h.BindPassword); err == nil {
			return c, nil
		}
		c.Close()
	default:
	}

	host, port, _ := net.SplitHostPort(h.URL.Host)

	ldaps := port == "636" || port == "3269" || h.URL.Scheme == "ldaps"
	if h.URL.Scheme == "ldap" {
		ldaps = false
	}
	if port == "" || port == "0" {
		port = "389"
		if ldaps {
			port = "636"
		}
	}

	hostPort := fmt.Sprintf("%s:%s", host, port)

	var err error
	if ldaps {
		c, err = ldp.DialTLS("tcp", hostPort, &tls.Config{InsecureSkipVerify: h.InsecureSkipVerify})
	} else {
		c, err = ldp.Dial("tcp", hostPort)
	}

	if err != nil {
		return nil, fmt.Errorf("connect to %q: %v", hostPort, err)
	}

	// Technically it's not impossible to run tls over ssl... just excessive
	if h.TLS {
		if err = c.StartTLS(&tls.Config{InsecureSkipVerify: h.InsecureSkipVerify}); err != nil {
			c.Close()
			return nil, fmt.Errorf("StartTLS: %v", err)
		}
	}

	if err := c.Bind(h.BindDN, h.BindPassword); err != nil {
		c.Close()
		return nil, fmt.Errorf("bind with %q: %v", h.BindDN, err)
	}

	return c, nil
}

func (h *LDAP) stashConnection(c ldp.Client) {
	select {
	case h.pool <- c:
		return
	default:
		c.Close()
		return
	}
}
