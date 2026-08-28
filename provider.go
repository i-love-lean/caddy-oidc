package caddy_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/relvacode/caddy-oidc/authenticator"
	"github.com/relvacode/caddy-oidc/internal/deferred"
	"github.com/relvacode/caddy-oidc/request"
	"github.com/relvacode/caddy-oidc/template"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type discoveryConfiguration struct {
	HttpClient  *http.Client
	Provider    *oidc.Provider
	Verifier    template.TokenVerifier
	OAuth2      *template.OAuth2ConfigTemplate
	TokenParams map[string]string
}

func (cfg *discoveryConfiguration) AuthCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) (string, error) {
	repl := template.MustReplacer(ctx)

	oauthCfg, err := cfg.OAuth2.Replace(repl)
	if err != nil {
		return "", err
	}

	return oauthCfg.AuthCodeURL(state, opts...), nil
}

func (cfg *discoveryConfiguration) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	repl := template.MustReplacer(ctx)

	ctx = context.WithValue(ctx, oauth2.HTTPClient, cfg.HttpClient)

	oauthCfg, err := cfg.OAuth2.Replace(repl)
	if err != nil {
		return nil, err
	}

	if len(cfg.TokenParams) > 0 {
		for urlParam, v := range cfg.TokenParams {
			pv, err := repl.ReplaceOrErr(v, false, true)
			if err != nil {
				return nil, fmt.Errorf("failed to replace token param %s: %w", urlParam, err)
			}

			opts = append(opts, oauth2.SetAuthURLParam(urlParam, pv))
		}
	}

	return oauthCfg.Exchange(ctx, code, opts...)
}

func (cfg *discoveryConfiguration) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, cfg.HttpClient)

	return cfg.Provider.UserInfo(ctx, tokenSource)
}

var (
	_ authenticator.OIDCConfiguration                   = (*Provider)(nil)
	_ authenticator.OAuthAuthorizationFlowConfiguration = (*Provider)(nil)
)

// Provider holds the built configuration for an OIDC provider and authentication logic.
type Provider struct {
	Log               *zap.Logger
	Clock             func() time.Time
	Issuer            string
	UsernameClaim     string
	ProtectedResource *ProtectedResourceMetadataConfiguration
	Authenticators    authenticator.Set
	Discovery         *deferred.Result[*discoveryConfiguration]
}

func (pr *Provider) Now() time.Time           { return pr.Clock() }
func (pr *Provider) GetUsernameClaim() string { return pr.UsernameClaim }

func (pr *Provider) GetVerifier(ctx context.Context) (template.TokenVerifier, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.Verifier, nil
}

func (pr *Provider) AuthCodeURL(ctx context.Context, state string, opts ...oauth2.AuthCodeOption) (string, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return "", err
	}

	return discovery.AuthCodeURL(ctx, state, opts...)
}

func (pr *Provider) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.Exchange(ctx, code, opts...)
}

func (pr *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error) {
	discovery, err := pr.Discovery.Get(ctx)
	if err != nil {
		return nil, err
	}

	return discovery.UserInfo(ctx, tokenSource)
}

// ProtectedResourceMetadata returns the OAuth protected resource metadata for this authenticator.
// If protected resource metadata is not enabled, then false is returned.
func (pr *Provider) ProtectedResourceMetadata(r *http.Request) (*OAuthProtectedResource, bool) {
	if pr.ProtectedResource.Disable {
		return nil, false
	}

	discovery, err := pr.Discovery.Get(r.Context())
	if err != nil {
		return nil, false
	}

	var (
		requestURL = request.URL(r)
		metadata   = &OAuthProtectedResource{
			Resource:        fmt.Sprintf("%s://%s", requestURL.Scheme, requestURL.Host),
			ScopesSupported: discovery.OAuth2.Scopes,
			AuthorizationServers: []string{
				pr.Issuer,
			},
			// OIDC middleware only supports bearer authentication via the Authorization header
			BearerMethodsSupported: []string{
				"header",
			},
		}
	)

	if pr.ProtectedResource.Audience {
		metadata.Audience, err = discovery.OAuth2.ClientID(template.MustReplacer(r.Context()))
		if err != nil {
			return nil, false
		}
	}

	return metadata, true
}

// WellKnownOAuthProtectedResourcePath is the path for the OAuth protected resource metadata endpoint.
const WellKnownOAuthProtectedResourcePath = "/.well-known/oauth-protected-resource"

// ServeHTTPOAuthProtectedResource returns the OAuth protected resource metadata for the endpoint
// .well-known/oauth-protected-resource.
// If the endpoint is disabled, then a 404 not found response is returned.
func (pr *Provider) ServeHTTPOAuthProtectedResource(rw http.ResponseWriter, r *http.Request) error {
	metadata, ok := pr.ProtectedResourceMetadata(r)
	if !ok {
		return caddyhttp.Error(http.StatusNotFound, errors.New("protected resource metadata is disabled"))
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")

	return enc.Encode(metadata)
}
