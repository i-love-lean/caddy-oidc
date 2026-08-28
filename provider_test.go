package caddy_oidc

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/relvacode/caddy-oidc/authenticator"
	"github.com/relvacode/caddy-oidc/internal/deferred"
	"github.com/relvacode/caddy-oidc/internal/pkgtest"
	"github.com/relvacode/caddy-oidc/template"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type HTTPTransportFunc func(req *http.Request) (*http.Response, error)

func (f HTTPTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDiscoveryConfiguration_Exchange_ReplacerVars(t *testing.T) {
	t.Parallel()

	var errTransportSentinel = errors.New("transport sentinel")

	c := &discoveryConfiguration{
		HttpClient: &http.Client{
			Transport: HTTPTransportFunc(func(req *http.Request) (*http.Response, error) {
				username, password, ok := req.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "REPLACED", username)
				assert.Equal(t, "REPLACED", password)

				return nil, errTransportSentinel
			}),
		},
		OAuth2: &template.OAuth2ConfigTemplate{
			TemplateClientID:     "{client_id}",
			TemplateClientSecret: "{client_secret}",
			Endpoint: oauth2.Endpoint{
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		},
		TokenParams: map[string]string{},
	}

	repl := caddy.NewEmptyReplacer()
	repl.Set("client_id", "REPLACED")
	repl.Set("client_secret", "REPLACED")

	ctx := context.WithValue(t.Context(), caddy.ReplacerCtxKey, repl)

	_, err := c.Exchange(ctx, "test-code")
	require.ErrorIs(t, err, errTransportSentinel)

	// Test that the template is not modified by running the test again
	_, err = c.Exchange(ctx, "test-code")
	require.ErrorIs(t, err, errTransportSentinel)
}

func TestDiscoveryConfiguration_Exchange_TokenParams(t *testing.T) {
	t.Parallel()

	var errTransportSentinel = errors.New("transport sentinel")

	c := &discoveryConfiguration{
		HttpClient: &http.Client{
			Transport: HTTPTransportFunc(func(req *http.Request) (*http.Response, error) {
				err := req.ParseForm()
				require.NoError(t, err)

				assert.Equal(t, "REPLACED", req.FormValue("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))

				return nil, errTransportSentinel
			}),
		},
		OAuth2: &template.OAuth2ConfigTemplate{
			TemplateClientID: "xyz",
			Endpoint: oauth2.Endpoint{
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		TokenParams: map[string]string{
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer": "{client_assertion}",
		},
	}

	repl := caddy.NewEmptyReplacer()
	repl.Set("client_assertion", "REPLACED")

	ctx := context.WithValue(t.Context(), caddy.ReplacerCtxKey, repl)

	_, err := c.Exchange(ctx, "test-code")
	assert.ErrorIs(t, err, errTransportSentinel)
}

func GenerateTestProvider() *Provider {
	cookie := &authenticator.SessionCookieAuthenticator{
		Name:   "test-cookie",
		Secret: "Y4lbVNr01M4NyBCUSNbrAL4cavA6kjdM",
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err := cookie.Provision(ctx)
	if err != nil {
		panic(err)
	}

	provider := &Provider{
		Clock: func() time.Time {
			return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		Authenticators: authenticator.Set{
			Authenticators: []authenticator.RequestAuthenticator{
				&authenticator.BearerAuthenticator{},
				cookie,
			},
		},
		ProtectedResource: new(ProtectedResourceMetadataConfiguration),
		Log:               zap.NewNop(),
		UsernameClaim:     DefaultUsernameClaim,
		Issuer:            "https://openid/example",
	}

	provider.Discovery = deferred.Defer(func() (*discoveryConfiguration, error) {
		return &discoveryConfiguration{
			Verifier: pkgtest.NewTestVerifier(provider.Clock),
			OAuth2: &template.OAuth2ConfigTemplate{
				TemplateClientID: "xyz",
				Scopes:           []string{"openid", "profile", "email", "offline_access"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  "http://openid/example/authorize",
					TokenURL: "http://openid/example/token",
				},
			},
		}, nil
	})

	return provider
}

func TestProvider_ProtectedResourceMetadata(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()

	r := pkgtest.NewRequest(http.MethodGet, "http://example.com/endpoint?x=y", nil)

	metadata, ok := pr.ProtectedResourceMetadata(r)
	assert.True(t, ok)
	assert.Equal(t, &OAuthProtectedResource{
		Resource:               "http://example.com",
		ScopesSupported:        []string{"openid", "profile", "email", "offline_access"},
		BearerMethodsSupported: []string{"header"},
		AuthorizationServers: []string{
			"https://openid/example",
		},
	}, metadata)
}

func TestProvider_ProtectedResourceMetadata_WithAudience(t *testing.T) {
	t.Parallel()

	pr := GenerateTestProvider()
	pr.ProtectedResource.Audience = true

	r := pkgtest.NewRequest(http.MethodGet, "http://example.com/endpoint?x=y", nil)

	d, _ := pr.Discovery.Get(r.Context())
	d.OAuth2.TemplateClientID = "{client_id}"

	template.MustReplacer(r.Context()).Set("client_id", "replaced")

	metadata, ok := pr.ProtectedResourceMetadata(r)
	assert.True(t, ok)
	assert.Equal(t, &OAuthProtectedResource{
		Resource:               "http://example.com",
		ScopesSupported:        []string{"openid", "profile", "email", "offline_access"},
		BearerMethodsSupported: []string{"header"},
		Audience:               "replaced",
		AuthorizationServers: []string{
			"https://openid/example",
		},
	}, metadata)
}
