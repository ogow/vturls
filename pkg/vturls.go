// vtclient.go
// Package vtclient provides a VirusTotal v2 client to fetch "undetected" URLs for a domain.
package vtclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client handles API key rotation and HTTP requests to VirusTotal v2.
type Client struct {
	apiKeys      []string
	currentIndex int
	httpClient   *http.Client
}

// NewClient returns a Client initialized with one or more API keys.
func NewClient(keys []string) (*Client, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one API key must be provided")
	}
	return &Client{
		apiKeys:    keys,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// CurrentKeyIndex returns the 1-based index of the key in use.
func (c *Client) CurrentKeyIndex() int {
	return c.currentIndex + 1
}

// RotateKey advances to the next API key in the list.
func (c *Client) RotateKey() {
	c.currentIndex = (c.currentIndex + 1) % len(c.apiKeys)
}

// doRequest executes the HTTP request, rotating keys on error or non-2xx status.
// If all keys have been tried and none succeed within one minute, it returns an error.
func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	start := time.Now()
	attempts := 0
	for {
		// timeout after 1 minute of trying all keys
		if time.Since(start) >= time.Minute {
			return nil, errors.New("all API keys failed after 1 minute")
		}
		resp, err := c.httpClient.Do(req)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		// rotate to next key
		c.RotateKey()
		attempts++
		// if cycled through all keys, wait briefly before retrying
		if attempts%len(c.apiKeys) == 0 {
			time.Sleep(time.Second)
		}
	}
}

// v2DomainReport represents the JSON response for the v2 domain report endpoint.
type v2DomainReport struct {
	UndetectedURLs [][]any `json:"undetected_urls"`
}

// FetchUndetectedURLs retrieves undetected URLs for the domain using v2 API.
func (c *Client) FetchUndetectedURLs(domain string) ([]string, error) {
	apiKey := c.apiKeys[c.currentIndex]
	endpoint := "https://www.virustotal.com/vtapi/v2/domain/report"
	// Build query parameters
	params := url.Values{}
	params.Set("apikey", apiKey)
	params.Set("domain", domain)
	reqURL := fmt.Sprintf("%s?%s", endpoint, params.Encode())

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var report v2DomainReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, err
	}

	var undetected []string
	for _, entry := range report.UndetectedURLs {
		if len(entry) > 0 {
			if urlStr, ok := entry[0].(string); ok {
				undetected = append(undetected, urlStr)
			}
		}
	}
	return undetected, nil
}

