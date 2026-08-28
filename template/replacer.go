package template

import (
	"context"

	"github.com/caddyserver/caddy/v2"
)

// MustReplacer returns a caddy replacer from the context.
// It panics if the replacer is not found.
func MustReplacer(ctx context.Context) *caddy.Replacer {
	//nolint:forcetypeassert // All Caddy HTTP requests will pass a context that contains a valid replacer
	repl := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	return repl
}
