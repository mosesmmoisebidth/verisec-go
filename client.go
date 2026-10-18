package verisec

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Version is the version of this library, sent in the User-Agent header.
const Version = "1.0.0"

const (
	// DefaultBaseURL is where requests go unless WithBaseURL or VERISEC_BASE_URL says otherwise.
	DefaultBaseURL = "https://verisec.mmose.me"
	// DefaultTimeout is how long one attempt may take. A deep cheque read can take up to about 250 seconds, and a
	// call cut off by the client may still finish, and be charged, on the server.
	DefaultTimeout = 300 * time.Second
	// DefaultMaxRetries is how many times a call is sent again when nothing can have been charged (so three
	// attempts in all).
	DefaultMaxRetries = 2
)

var (
	// ErrNoAPIKey is returned by New when it gets no API key and VERISEC_API_KEY is unset.
	ErrNoAPIKey = errors.New("verisec: no API key: pass one to verisec.New or set VERISEC_API_KEY")
	// ErrNoClientCredentials is returned by New for a live key (ak_live_…) without its client id and secret.
	ErrNoClientCredentials = errors.New("verisec: a live key (ak_live_…) also needs its client id and secret: pass verisec.WithClientCredentials(id, secret), or set VERISEC_CLIENT_ID and VERISEC_CLIENT_SECRET")
)

// A ClientOption configures a Client. Pass options to New.
type ClientOption func(*clientConfig)

type clientConfig struct {
	clientID     string
	clientSecret string
	baseURL      string
	timeout      time.Duration
	maxRetries   int
	httpClient   *http.Client
}

// WithClientCredentials sets the client id and secret issued with a live API key (ak_live_…). The client
// exchanges the three at POST /v2/oauth/token for a short-lived bearer token, keeps it until a minute before it
// expires (concurrent calls share one exchange), and fetches a new one once when the API answers 401.
//
// Without this option, VERISEC_CLIENT_ID and VERISEC_CLIENT_SECRET are used.
func WithClientCredentials(clientID, clientSecret string) ClientOption {
	return func(c *clientConfig) {
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

// WithBaseURL sends requests to another host, such as a local test server. Defaults to VERISEC_BASE_URL, then
// https://verisec.mmose.me.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *clientConfig) { c.baseURL = baseURL }
}

// WithTimeout sets how long one attempt may take, reading the answer included. Defaults to 300 seconds; 0 means
// no limit. A call that times out is not sent again, because it may still run (and be charged) on the server;
// bound the whole call, retries included, with the context's deadline.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.timeout = max(d, 0) }
}

// WithMaxRetries sets how many times a call is sent again after a 429, a 5xx or a connection that never opened.
// Defaults to 2; 0 turns retries off.
func WithMaxRetries(n int) ClientOption {
	return func(c *clientConfig) { c.maxRetries = max(n, 0) }
}

// WithHTTPClient sends requests through your own *http.Client, for proxies, custom TLS or instrumentation.
// Leave its Timeout at zero: the client times each attempt itself (WithTimeout).
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *clientConfig) { c.httpClient = hc }
}

// New returns a client for an API key: a test key (sk_test_…), sent as the bearer token, or a live key
// (ak_live_…) together with WithClientCredentials. An empty key falls back to VERISEC_API_KEY.
//
// It returns ErrNoAPIKey without a key, ErrNoClientCredentials for a live key without its client id and secret,
// and an error for a base URL that is not absolute. The client is safe for concurrent use: create one and share it.
func New(apiKey string, opts ...ClientOption) (*Client, error) {
	cfg := clientConfig{timeout: DefaultTimeout, maxRetries: DefaultMaxRetries}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if apiKey == "" {
		apiKey = os.Getenv("VERISEC_API_KEY")
	}
	if cfg.baseURL == "" {
		cfg.baseURL = os.Getenv("VERISEC_BASE_URL")
	}
	if cfg.baseURL == "" {
		cfg.baseURL = DefaultBaseURL
	}
	if cfg.clientID == "" {
		cfg.clientID = os.Getenv("VERISEC_CLIENT_ID")
	}
	if cfg.clientSecret == "" {
		cfg.clientSecret = os.Getenv("VERISEC_CLIENT_SECRET")
	}
	if cfg.httpClient == nil {
		cfg.httpClient = &http.Client{}
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, ErrNoAPIKey
	}
	base := strings.TrimRight(cfg.baseURL, "/")
	if u, err := url.Parse(base); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("verisec: the base URL %q is not an absolute URL", cfg.baseURL)
	}

	t := &transport{
		baseURL:    base,
		timeout:    cfg.timeout,
		maxRetries: cfg.maxRetries,
		http:       cfg.httpClient,
		sleep:      sleepContext,
	}
	if strings.HasPrefix(apiKey, "ak_live_") {
		if cfg.clientID == "" || cfg.clientSecret == "" {
			return nil, ErrNoClientCredentials
		}
		t.creds = newClientCredentials(t, apiKey, cfg.clientID, cfg.clientSecret)
	} else {
		t.creds = secretKey(apiKey)
	}
	return newClient(t), nil
}
