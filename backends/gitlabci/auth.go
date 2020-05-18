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

package gitlabci

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/freman/caddy2-reauth/backends"
	"github.com/freman/caddy2-reauth/jsontypes"
)

// Interface guard
var _ backends.Driver = (*GitlabCI)(nil)

// BackendName name
const BackendName = "gitlabci"

const defaultTimeout = time.Minute
const defaultUsername = "gitlab-ci-token"

// GitlabCI backend provides authentication against gitlab paths, primarily to make
// it easier to dynamically authenticate the gitlab-ci against gitlab permitting
// testing access to otherwise private resources without storing credentials in
// gitlab or gitlab-ci.yml
//
// Authenticating against this backend should be done with the project path as
// the username and the token as the password.
//
// Example: docker login docker.example.com -u "$CI_PROJECT_PATH" -p "$CI_BUILD_TOKEN"
type GitlabCI struct {
	URL                *jsontypes.URL     `json:"url,omitempty"`
	Timeout            jsontypes.Duration `json:"timeout,omitempty"`
	Username           string             `json:"username,omitempty"`
	InsecureSkipVerify bool               `json:"insecure_skip_verify,omitempty"`
}

// NewDriver returns a GitlabCI instance with some defaults
func NewDriver() *GitlabCI {
	return &GitlabCI{
		Timeout:  jsontypes.Duration{Duration: defaultTimeout},
		Username: defaultUsername,
	}
}

// Validate that this module is ready to go
func (h GitlabCI) Validate() error {
	if h.Username == "" {
		return errors.New("username is a required option")
	}

	if h.Timeout.Duration <= 0 {
		return errors.New("timeout must be greater than 0")
	}

	if h.URL == nil {
		return errors.New("url to auth against is a required parameter")
	}

	return nil
}

func noRedirectsPolicy(req *http.Request, via []*http.Request) error {
	return errors.New("follow redirects disabled")
}

// Authenticate fulfils the backend interface
func (h GitlabCI) Authenticate(r *http.Request) (string, error) {
	un, pw, k := r.BasicAuth()
	if !k {
		return "", nil
	}

	repo, err := h.URL.Parse(un + ".git/info/refs?service=git-upload-pack")
	if err != nil {
		return "", fmt.Errorf("unable to parse repo path: %v", err)
	}

	c := &http.Client{
		Timeout:       h.Timeout.Duration,
		CheckRedirect: noRedirectsPolicy,
	}

	if repo.Scheme == "https" && h.InsecureSkipVerify {
		c.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest("GET", repo.String(), nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(h.Username, pw)

	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}

	resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code from gitlabci: %d (%s)", resp.StatusCode, resp.Status)
	}

	return un, nil
}
