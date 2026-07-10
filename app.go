// Package caddy_oidc is a Caddy plugin for providing authentication and authorization using an OIDC IdP
package caddy_oidc

import (
	"encoding/json"
	"fmt"

	"github.com/huandu/go-clone/generic"
	"github.com/relvacode/caddy-oidc/internal/lazy"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/relvacode/caddy-oidc/authenticator" // Registers the built-in authenticator modules
)

const moduleID = "oidc"

func init() {
	caddy.RegisterModule(new(App))
	httpcaddyfile.RegisterGlobalOption("oidc", parseGlobalConfig)
}

func parseGlobalConfig(d *caddyfile.Dispenser, prev any) (any, error) {
	var app App

	switch prev := prev.(type) {
	case httpcaddyfile.App:
		err := json.Unmarshal(prev.Value, &app)
		if err != nil {
			return nil, err
		}
	case nil:
		// Hasn't been initialized yet
	default:
		return nil, fmt.Errorf("conflicting global parser option for the oidc directive: %T", prev)
	}

	for d.Next() {
		var mod = &app.Default

		// If there is a next argument in the dispener
		// then we'll treat that as a named provider
		// which clones from the current default configuration.
		if d.NextArg() {
			var name = d.Val()

			if app.Providers == nil {
				app.Providers = make(map[string]*OIDCProviderModule)
			}

			mod = clone.Clone(&app.Default)
			app.Providers[name] = mod
		}

		err := mod.UnmarshalCaddyfile(d)
		if err != nil {
			return nil, err
		}
	}

	return httpcaddyfile.App{
		Name:  moduleID,
		Value: caddyconfig.JSON(&app, nil),
	}, nil
}

func parseCaddyfileHandler[T any, Ptr interface {
	*T
	caddyfile.Unmarshaler
	caddyhttp.MiddlewareHandler
}](h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(T)

	err := Ptr(handler).UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}

	return Ptr(handler), nil
}

var _ caddy.App = (*App)(nil)
var _ caddy.Module = (*App)(nil)

// App holds configuration for all the named OIDC providers within a Caddy configuration.
type App struct {
	// Default contains the default / baseline OIDC configuration for this App.
	// The Default is used as a baseline configuration during caddyfile unmarshalling of named providers
	// and can be referenced directly in an OIDCMiddleware when a provider is not defined.
	Default   OIDCProviderModule             `json:"default"`
	Providers map[string]*OIDCProviderModule `json:"providers,omitempty"`

	provisioned map[string]*lazy.Lazy[*Provider]
}

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  moduleID,
		New: func() caddy.Module { return new(App) },
	}
}

func (*App) Start() error { return nil }
func (*App) Stop() error  { return nil }

func (a *App) getProviderModule(name string) (*OIDCProviderModule, error) {
	if name == "" {
		return &a.Default, nil
	}

	mod, ok := a.Providers[name]
	if !ok {
		return nil, fmt.Errorf("oidc: named provider '%s' is not configured", name)
	}

	return mod, nil
}

// displayName returns the display name for the given provider name.
// As we use an empty string to reference the default provider,
// it makes sense to use a placeholder value instead for the default
// so that it's obvious in errors and logs that the referencee is using the default configuration.
func displayName(name string) string {
	if name == "" {
		return "<default>"
	}

	return name
}

func (a *App) ProvisionProvider(ctx caddy.Context, name string) (*Provider, error) {
	if a.provisioned == nil {
		a.provisioned = make(map[string]*lazy.Lazy[*Provider])
	}

	init, ok := a.provisioned[name]

	// Named provisioned provider has not been set up yet
	if !ok {
		mod, err := a.getProviderModule(name)
		if err != nil {
			return nil, err
		}

		// Lazily provision the provider exactly once.
		// Only the first instance of provisioning gets the contents of the caddy.Context.
		init = lazy.New(func() (*Provider, error) {
			err := mod.Provision(ctx)
			if err != nil {
				return nil, fmt.Errorf("provision: %w", err)
			}

			err = mod.Validate()
			if err != nil {
				return nil, fmt.Errorf("validate: %w", err)
			}

			return mod.Create(ctx)
		})

		a.provisioned[name] = init
	}

	pr, err := init.Get()
	if err != nil {
		return nil, fmt.Errorf("oidc: provider '%s': %w", displayName(name), err)
	}

	return pr, nil
}
