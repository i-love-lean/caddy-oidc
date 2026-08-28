package template

import (
	"context"
	"fmt"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
)

// TokenVerifier provides a method for parsing and verifying an ID token.
type TokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// ReplacerTokenVerifier wraps the behavior of the oidc.IDTokenVerifier
// so that the client ID (audience) is verified using a request-time replaced value.
type ReplacerTokenVerifier struct {
	clientID string
	verifier *oidc.IDTokenVerifier
}

// NewTokenVerifierTemplate returns a new ReplacerTokenVerifier from the provided oidc.Provider,
// configuring the verifier to skip client ID check in favor of a request-time replaced client ID.
func NewTokenVerifierTemplate(clientID string, provider *oidc.Provider) *ReplacerTokenVerifier {
	return &ReplacerTokenVerifier{
		clientID: clientID,
		verifier: provider.Verifier(&oidc.Config{
			// (security) Explicitly disable client ID check by the verifier directly.
			// The TokenVerifierTemplate will perform the post-verification client ID check against the replaced client ID.
			SkipClientIDCheck: true,
		}),
	}
}

func (t *ReplacerTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	token, err := t.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	clientID, err := MustReplacer(ctx).ReplaceOrErr(t.clientID, true, true)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(token.Audience, clientID) {
		return nil, fmt.Errorf("oidc: expected audience %q got %q", clientID, token.Audience)
	}

	return token, nil
}
