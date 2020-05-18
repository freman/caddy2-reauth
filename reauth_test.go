package reauth_test

import (
	"io/ioutil"
	"net/url"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestReauth(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL, _ := url.Parse("http://127.0.0.1:9080")

	rootURL, _ := baseURL.Parse("/")
	secretURL, _ := baseURL.Parse("/secret")
	authenticatedURL, _ := baseURL.Parse("/secret")
	authenticatedURL.User = url.UserPassword("username", "password")

	// Load configuration file
	configFile := "assets/conf/Caddyfile.json"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}

	rawConfig := string(configContent)

	tester.InitServer(rawConfig, "json")
	tester.AssertGetResponse(rootURL.String(), 200, "hello world")
	tester.AssertGetResponse(secretURL.String(), 403, "")
	tester.AssertGetResponse(authenticatedURL.String(), 200, "tell no-one")

}
