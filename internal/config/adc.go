// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ADCScopes lists the OAuth2 scopes required when authenticating via Google
// Cloud Application Default Credentials (ADC) against
// generativelanguage.googleapis.com (matching dr-cli).
var ADCScopes = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/generative-language.retriever",
	"https://www.googleapis.com/auth/generative-language.tuning",
	"https://www.googleapis.com/auth/generative-language.peruserquota",
}

// ADCLoginCommand is the gcloud command that configures Application Default
// Credentials with the generative-language scopes required by the Gemini API.
const ADCLoginCommand = "gcloud auth application-default login --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/generative-language.retriever,https://www.googleapis.com/auth/generative-language.tuning,https://www.googleapis.com/auth/generative-language.peruserquota"

const defaultGoogleTokenURI = "https://oauth2.googleapis.com/token"

type adcCredentialsFile struct {
	Type           string `json:"type"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	RefreshToken   string `json:"refresh_token"`
	ClientEmail    string `json:"client_email"`
	PrivateKey     string `json:"private_key"`
	TokenURI       string `json:"token_uri"`
	QuotaProjectID string `json:"quota_project_id"`
}

func (c *adcCredentialsFile) isValid() bool {
	if c == nil {
		return false
	}
	switch c.Type {
	case "authorized_user":
		return strings.TrimSpace(c.ClientID) != "" &&
			strings.TrimSpace(c.ClientSecret) != "" &&
			strings.TrimSpace(c.RefreshToken) != ""
	case "service_account":
		return strings.TrimSpace(c.ClientEmail) != "" &&
			strings.TrimSpace(c.PrivateKey) != ""
	default:
		return false
	}
}

type cachedADCToken struct {
	path      string
	modTime   time.Time
	token     string
	expiresAt time.Time
}

var (
	adcMu           sync.Mutex
	adcCache        cachedADCToken
	adcTokenURI     = defaultGoogleTokenURI
	adcHTTPClient   = &http.Client{Timeout: 10 * time.Second}
)

func resetADCState() {
	adcMu.Lock()
	defer adcMu.Unlock()
	adcCache = cachedADCToken{}
	adcTokenURI = defaultGoogleTokenURI
}

// SetADCTokenURIForTest overrides the default OAuth2 token endpoint in tests.
func SetADCTokenURIForTest(uri string) {
	adcMu.Lock()
	defer adcMu.Unlock()
	adcCache = cachedADCToken{}
	if strings.TrimSpace(uri) == "" {
		adcTokenURI = defaultGoogleTokenURI
	} else {
		adcTokenURI = uri
	}
}

// ADCFilePath returns the path to the Google Cloud Application Default
// Credentials JSON file, checking GOOGLE_APPLICATION_CREDENTIALS,
// CLOUDSDK_CONFIG, and the platform-default gcloud config directory.
func ADCFilePath() string {
	if p := strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")); p != "" {
		return p
	}
	if cfgDir := strings.TrimSpace(os.Getenv("CLOUDSDK_CONFIG")); cfgDir != "" {
		return filepath.Join(cfgDir, "application_default_credentials.json")
	}
	if runtime.GOOS == "windows" {
		if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
			return filepath.Join(appData, "gcloud", "application_default_credentials.json")
		}
	}
	homeDir, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return ""
	}
	return filepath.Join(homeDir, ".config", "gcloud", "application_default_credentials.json")
}

func loadADCFile() (*adcCredentialsFile, string, time.Time, error) {
	path := ADCFilePath()
	if path == "" {
		return nil, "", time.Time{}, errors.New("no ADC path resolved")
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, path, time.Time{}, fmt.Errorf("stat ADC file: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, time.Time{}, fmt.Errorf("read ADC file: %w", err)
	}
	var creds adcCredentialsFile
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, path, time.Time{}, fmt.Errorf("parse ADC file: %w", err)
	}
	if !creds.isValid() {
		return nil, path, time.Time{}, errors.New("unsupported or incomplete ADC file")
	}
	return &creds, path, info.ModTime(), nil
}

// HasADC reports whether a readable, structurally valid Google Cloud
// Application Default Credentials file is present on disk, without making any
// network calls.
func HasADC() bool {
	_, _, _, err := loadADCFile()
	return err == nil
}

// ResolveADCAccessToken loads Application Default Credentials from disk and
// exchanges them for an OAuth2 access token (with in-process caching). Returns
// "" if no ADC file is available or token exchange fails.
func ResolveADCAccessToken() string {
	creds, path, modTime, err := loadADCFile()
	if err != nil {
		return ""
	}

	adcMu.Lock()
	defer adcMu.Unlock()

	now := time.Now()
	if adcCache.token != "" &&
		adcCache.path == path &&
		adcCache.modTime.Equal(modTime) &&
		now.Before(adcCache.expiresAt) {
		return adcCache.token
	}

	token, expiresIn, err := fetchADCToken(creds, adcTokenURI, adcHTTPClient)
	if err != nil || token == "" {
		return ""
	}

	ttl := time.Duration(expiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	if ttl > 2*time.Minute {
		ttl -= time.Minute
	}
	adcCache = cachedADCToken{
		path:      path,
		modTime:   modTime,
		token:     token,
		expiresAt: now.Add(ttl),
	}
	return token
}

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func fetchADCToken(creds *adcCredentialsFile, fallbackTokenURI string, client *http.Client) (string, int64, error) {
	tokenURI := strings.TrimSpace(creds.TokenURI)
	if tokenURI == "" {
		tokenURI = fallbackTokenURI
	}

	var form url.Values
	switch creds.Type {
	case "authorized_user":
		form = url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {creds.ClientID},
			"client_secret": {creds.ClientSecret},
			"refresh_token": {creds.RefreshToken},
		}
	case "service_account":
		assertion, err := buildServiceAccountJWT(creds, tokenURI, ADCScopes)
		if err != nil {
			return "", 0, err
		}
		form = url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {assertion},
		}
	default:
		return "", 0, fmt.Errorf("unsupported ADC type %q", creds.Type)
	}

	req, err := http.NewRequest(http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}

	var parsed oauthTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, err
	}
	return strings.TrimSpace(parsed.AccessToken), parsed.ExpiresIn, nil
}

type serviceAccountJWTClaims struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

func buildServiceAccountJWT(creds *adcCredentialsFile, tokenURI string, scopes []string) (string, error) {
	rsaKey, err := parseRSAPrivateKey(creds.PrivateKey)
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	headerJSON := []byte(`{"alg":"RS256","typ":"JWT"}`)
	claimsJSON, err := json.Marshal(serviceAccountJWTClaims{
		Iss:   creds.ClientEmail,
		Scope: strings.Join(scopes, " "),
		Aud:   tokenURI,
		Iat:   now,
		Exp:   now + 3600 - 5,
	})
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func parseRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("invalid PEM private key in service account credentials")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("PKCS#8 private key is not RSA")
	}
	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}
	return nil, errors.New("failed to parse RSA private key")
}
