package template

import (
	"context"

	"github.com/caddyserver/caddy/v2"
)

func MustReplacer(ctx context.Context) *caddy.Replacer {
	repl := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	return repl
}
