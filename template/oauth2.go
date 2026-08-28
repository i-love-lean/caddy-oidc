package template

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"golang.org/x/oauth2"
)

// OAuth2ConfigTemplate stores a baseline oauth2.Config constructed through OIDC Discovery.
// Select fields are then replaced at request time with Caddy replacer values.
type OAuth2ConfigTemplate struct {
	TemplateClientID     string
	TemplateClientSecret string
	Endpoint             oauth2.Endpoint
	Scopes               []string
}

func (t *OAuth2ConfigTemplate) ClientID(repl *caddy.Replacer) (string, error) {
	return repl.ReplaceOrErr(t.TemplateClientID, false, true)
}

func (t *OAuth2ConfigTemplate) Replace(repl *caddy.Replacer) (*oauth2.Config, error) {
	cfg := oauth2.Config{
		Endpoint: t.Endpoint,
		Scopes:   t.Scopes,
	}

	var err error

	cfg.ClientID, err = t.ClientID(repl)
	if err != nil {
		return nil, fmt.Errorf("failed to replace client ID: %w", err)
	}

	cfg.ClientSecret, err = repl.ReplaceOrErr(t.TemplateClientSecret, false, true)
	if err != nil {
		return nil, fmt.Errorf("failed to replace client secret: %w", err)
	}

	return &cfg, nil
}
