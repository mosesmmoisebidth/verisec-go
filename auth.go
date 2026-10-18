package verisec

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// credentials supply the bearer token of each request.
type credentials interface {
	// token returns the bearer token for the next request.
	token(ctx context.Context) (string, error)
	// invalidate forgets a token the API rejected with a 401. It reports whether fetching a new one and
	// sending the call again can help.
	invalidate(rejected string) bool
}

// secretKey is a test key (sk_test_…), sent as the bearer token itself.
type secretKey string

func (k secretKey) token(context.Context) (string, error) { return string(k), nil }

func (secretKey) invalidate(string) bool { return false }

// oauthTokenRequest is the body of POST /v2/oauth/token.
type oauthTokenRequest struct {
	GrantType    string `json:"grant_type"`
	APIKey       string `json:"api_key"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// oauthTokenResponse is the token endpoint's answer. expires_in may come with a fraction.
type oauthTokenResponse struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresIn   *float64 `json:"expires_in"`
	Scope       string   `json:"scope"`
}

// tokenRenewMargin is how long before it expires a token is replaced.
const tokenRenewMargin = 60 * time.Second

// clientCredentials exchanges a live API key (ak_live_…) with its client id and secret at
// POST /v2/oauth/token for a short-lived bearer token. The token is kept until 60 seconds before it expires,
// and concurrent callers share one exchange.
type clientCredentials struct {
	exchange func(ctx context.Context) (*oauthTokenResponse, error)
	now      func() time.Time

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
	inflight  *tokenFetch
}

// tokenFetch is one exchange that several callers may wait for.
type tokenFetch struct {
	done  chan struct{}
	token string
	err   error
}

func newClientCredentials(t *transport, apiKey, clientID, clientSecret string) *clientCredentials {
	body := &oauthTokenRequest{GrantType: "client_credentials", APIKey: apiKey, ClientID: clientID, ClientSecret: clientSecret}
	return &clientCredentials{
		now: time.Now,
		exchange: func(ctx context.Context) (*oauthTokenResponse, error) {
			res := new(oauthTokenResponse)
			// The exchange carries no bearer token, and is not sent again: a refused exchange fails the call.
			c := &call{method: http.MethodPost, path: "/v2/oauth/token", body: body, anonymous: true, noRetries: true}
			if err := t.do(ctx, c, res, nil); err != nil {
				return nil, err
			}
			return res, nil
		},
	}
}

func (c *clientCredentials) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.cached != "" && c.now().Before(c.expiresAt) {
		token := c.cached
		c.mu.Unlock()
		return token, nil
	}
	fetch := c.inflight
	if fetch == nil {
		fetch = &tokenFetch{done: make(chan struct{})}
		c.inflight = fetch
		// The exchange outlives a caller that gives up, so the others waiting for it still get the token.
		// Its own timeout bounds it.
		go c.fetch(context.WithoutCancel(ctx), fetch)
	}
	c.mu.Unlock()

	select {
	case <-fetch.done:
		return fetch.token, fetch.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *clientCredentials) fetch(ctx context.Context, fetch *tokenFetch) {
	res, err := c.exchange(ctx)
	if err == nil && res.AccessToken == "" {
		err = errors.New("verisec: the token endpoint returned no access_token")
	}

	c.mu.Lock()
	if err == nil {
		lifetime := time.Hour
		if res.ExpiresIn != nil {
			lifetime = time.Duration(*res.ExpiresIn * float64(time.Second))
		}
		c.cached = res.AccessToken
		c.expiresAt = c.now().Add(max(lifetime-tokenRenewMargin, 0))
		fetch.token = res.AccessToken
	}
	fetch.err = err
	c.inflight = nil
	c.mu.Unlock()
	close(fetch.done)
}

// invalidate forgets the rejected token, unless another caller already replaced it.
func (c *clientCredentials) invalidate(rejected string) bool {
	c.mu.Lock()
	if c.cached == rejected {
		c.cached = ""
	}
	c.mu.Unlock()
	return true
}
