package template

import (
	"context"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
)

type testTokenVerifier struct{}

func (t testTokenVerifier) Verify(_ context.Context, _ string) (*oidc.IDToken, error) {
	return &oidc.IDToken{Audience: []string{"a", "b", "c"}}, nil
}

func TestReplacerTokenVerifier_Verify(t *testing.T) {
	t.Parallel()

	verifier := &ReplacerTokenVerifier{
		clientID: "{client_id}",
		verifier: testTokenVerifier{},
	}

	repl := caddy.NewReplacer()

	ctx := context.WithValue(t.Context(), caddy.ReplacerCtxKey, repl)

	//nolint:paralleltest
	t.Run("Without Placeholder Variable", func(t *testing.T) {
		_, err := verifier.Verify(ctx, "")
		assert.ErrorContains(t, err, "unrecognized placeholder")
	})

	//nolint:paralleltest
	t.Run("With Valid Audience", func(t *testing.T) {
		repl.Set("client_id", "b")

		_, err := verifier.Verify(ctx, "")
		assert.NoError(t, err)
	})

	//nolint:paralleltest
	t.Run("With Invalid Audience", func(t *testing.T) {
		repl.Set("client_id", "d")

		_, err := verifier.Verify(ctx, "")

		var expectedErr ExpectedAudienceError
		assert.ErrorAs(t, err, &expectedErr)
	})
}
