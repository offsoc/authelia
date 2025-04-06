package oidc

import (
	"net/url"
	"time"

	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	"authelia.com/provider/oauth2/token/jwt"
	"github.com/google/uuid"
	"github.com/mohae/deepcopy"

	"github.com/authelia/authelia/v4/internal/model"
)

// NewSession creates a new empty OpenIDSession struct with the requested at value being time.Now().
func NewSession() (session *Session) {
	return NewSessionWithRequestedAt(time.Now())
}

// NewSessionWithRequestedAt creates a new empty OpenIDSession struct with a specific requested at value.
func NewSessionWithRequestedAt(requestedAt time.Time) (session *Session) {
	session = &Session{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Extra: map[string]any{},
			},
			Headers: &jwt.Headers{
				Extra: map[string]any{},
			},
		},
		Extra: map[string]any{},
	}

	session.SetRequestedAt(requestedAt.UTC())

	return session
}

// NewSessionWithRequester uses details from a Requester to generate an OpenIDSession.
func NewSessionWithRequester(ctx Context, issuer *url.URL, kid, username string, amr []string, extra map[string]any,
	authTime time.Time, consent *model.OAuth2ConsentSession, requester oauthelia2.Requester, claims *ClaimsRequests) (session *Session) {
	if extra == nil {
		extra = map[string]any{}
	}

	session = &Session{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Issuer:                              issuer.String(),
				Subject:                             consent.Subject.UUID.String(),
				Audience:                            nil,
				ExpirationTime:                      nil,
				IssuedAt:                            jwt.NewNumericDate(ctx.GetClock().Now()),
				AuthTime:                            jwt.NewNumericDate(authTime),
				Nonce:                               requester.GetRequestForm().Get(ClaimNonce),
				AuthenticationContextClassReference: "",
				AuthenticationMethodsReferences:     amr,
				AuthorizedParty:                     requester.GetClient().GetID(),
				AccessTokenHash:                     "",
				CodeHash:                            "",
				StateHash:                           "",
				Extra:                               extra,
			},
			Headers: &jwt.Headers{
				Extra: map[string]any{
					JWTHeaderKeyIdentifier: kid,
				},
			},
			Username:    username,
			Subject:     consent.Subject.UUID.String(),
			RequestedAt: consent.RequestedAt.UTC(),
		},
		ChallengeID:           model.NullUUID(consent.ChallengeID),
		KID:                   "",
		ClientID:              requester.GetClient().GetID(),
		ClientCredentials:     false,
		ExcludeNotBeforeClaim: false,
		AllowedTopLevelClaims: nil,
		ClaimRequests:         claims,
		GrantedClaims:         consent.GrantedClaims,
		Extra:                 map[string]any{},
	}

	return session
}

// Session holds OpenID Connect 1.0 Session information.
type Session struct {
	*openid.DefaultSession `json:"id_token"`

	ChallengeID           uuid.NullUUID   `json:"challenge_id"`
	KID                   string          `json:"kid"`
	ClientID              string          `json:"client_id"`
	ClientCredentials     bool            `json:"client_credentials"`
	ExcludeNotBeforeClaim bool            `json:"exclude_nbf_claim"`
	AllowedTopLevelClaims []string        `json:"allowed_top_level_claims"`
	ClaimRequests         *ClaimsRequests `json:"claim_requests,omitempty"`
	GrantedClaims         []string        `json:"granted_claims,omitempty"`
	Extra                 map[string]any  `json:"extra"`
}

// GetChallengeID returns the challenge id.
func (s *Session) GetChallengeID() (challenge uuid.NullUUID) {
	return s.ChallengeID
}

// GetJWTHeader returns the *jwt.Headers for the OAuth 2.0 JWT Profile Access Token.
func (s *Session) GetJWTHeader() (headers *jwt.Headers) {
	headers = &jwt.Headers{
		Extra: map[string]any{
			JWTHeaderKeyType: JWTHeaderTypeValueAccessTokenJWT,
		},
	}

	if len(s.KID) != 0 {
		headers.Extra[JWTHeaderKeyIdentifier] = s.KID
	}

	return headers
}

// GetJWTClaims returns the jwt.JWTClaimsContainer for the OAuth 2.0 JWT Profile Access Tokens.
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	//nolint:prealloc
	var (
		allowed []string
		amr     bool
	)

	for _, cl := range s.AllowedTopLevelClaims {
		switch cl {
		case ClaimJWTID, ClaimIssuer, ClaimSubject, ClaimAudience, ClaimExpirationTime, ClaimNotBefore, ClaimIssuedAt, ClaimClientIdentifier, ClaimScopeNonStandard, ClaimExtra:
			continue
		case ClaimAuthenticationMethodsReference:
			amr = true

			continue
		}

		allowed = append(allowed, cl)
	}

	claims := &jwt.JWTClaims{
		Subject:   s.Subject,
		ExpiresAt: s.GetExpiresAt(oauthelia2.AccessToken),
		IssuedAt:  time.Now().UTC(),
		Extra:     map[string]any{},
	}

	if len(s.Extra) > 0 {
		claims.Extra[ClaimExtra] = s.Extra
	}

	if s.DefaultSession != nil && s.DefaultSession.Claims != nil {
		for _, allowedClaim := range allowed {
			if cl, ok := s.DefaultSession.Claims.Extra[allowedClaim]; ok {
				claims.Extra[allowedClaim] = cl
			}
		}

		claims.Issuer = s.DefaultSession.Claims.Issuer

		if amr && len(s.DefaultSession.Claims.AuthenticationMethodsReferences) != 0 {
			claims.Extra[ClaimAuthenticationMethodsReference] = s.DefaultSession.Claims.AuthenticationMethodsReferences
		}
	}

	if len(s.ClientID) != 0 {
		claims.Extra[ClaimClientIdentifier] = s.ClientID
	}

	return claims
}

// GetIDTokenClaims returns the *jwt.IDTokenClaims for this session.
func (s *Session) GetIDTokenClaims() (claims *jwt.IDTokenClaims) {
	if s.DefaultSession == nil {
		return nil
	}

	return s.DefaultSession.Claims
}

// GetExtraClaims returns the Extra/Unregistered claims for this session.
func (s *Session) GetExtraClaims() map[string]any {
	return s.Extra
}

// Clone copies the OpenIDSession to a new oauthelia2.Session.
func (s *Session) Clone() oauthelia2.Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(oauthelia2.Session)
}
