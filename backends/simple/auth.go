/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Shannon Wynter
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

package simple

import (
	"net/http"

	"github.com/freman/caddy2-reauth/backends"
	"golang.org/x/crypto/bcrypt"
)

// Interface guard
var _ backends.Driver = (*Simple)(nil)

// BackendName name
const BackendName = "simple"

// Simple is the simplest backend for authentication, a name:password map
type Simple struct {
	UseBcrypt   bool              `json:"use_bcrypt,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

// NewDriver returns a new instance of Simple with some defaults
func NewDriver() *Simple {
	return &Simple{
		Credentials: map[string]string{},
	}
}

// Validate verifies that this module is functional with the given configuration
func (h Simple) Validate() error {
	return nil
}

// Authenticate fulfils the backend interface
func (h Simple) Authenticate(r *http.Request) (string, error) {
	un, pw, k := r.BasicAuth()
	if !k {
		return "", nil
	}

	if p, found := h.Credentials[un]; found {
		if h.UseBcrypt {
			if bcrypt.CompareHashAndPassword([]byte(p), []byte(pw)) == nil {
				return un, nil
			}

			return "", nil
		}

		if p == pw {
			return un, nil
		}
	}

	return "", nil
}
