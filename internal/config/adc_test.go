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

package config_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google-gemini/gemini-api-cli/internal/config"
	"github.com/spf13/cobra"
)

func newTestCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "gemini-api"}
	cmd.PersistentFlags().String("api-key", "", "")
	cmd.PersistentFlags().String("access-token", "", "")
	cmd.PersistentFlags().Bool("dry-run", false, "")
	cmd.PersistentFlags().Bool("no-keyring", false, "")
	return cmd
}

func isolateADCEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_CONFIG", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GEMINI_ACCESS_TOKEN", "")
	config.Reset()
	config.ResetKeyring()
	config.DisableKeyring()
	if err := config.Init("gemini-api", "GEMINI"); err != nil {
		t.Fatalf("config.Init: %v", err)
	}
	t.Cleanup(func() {
		config.Reset()
		config.ResetKeyring()
	})
	return home
}

func TestADCAuthorizedUserResolutionAndCaching(t *testing.T) {
	home := isolateADCEnv(t)

	var hits atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", got)
		}
		if got := r.Form.Get("client_id"); got != "test-client-id" {
			t.Errorf("client_id = %q, want test-client-id", got)
		}
		if got := r.Form.Get("client_secret"); got != "test-client-secret" {
			t.Errorf("client_secret = %q, want test-client-secret", got)
		}
		if got := r.Form.Get("refresh_token"); got != "test-refresh-token" {
			t.Errorf("refresh_token = %q, want test-refresh-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"ya29.adc-user-token","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer tokenServer.Close()
	config.SetADCTokenURIForTest(tokenServer.URL)

	if config.HasADC() {
		t.Fatal("HasADC() = true before writing ADC file, want false")
	}

	gcloudDir := filepath.Join(home, ".config", "gcloud")
	if err := os.MkdirAll(gcloudDir, 0o700); err != nil {
		t.Fatal(err)
	}
	adcJSON := `{
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "refresh_token": "test-refresh-token",
  "type": "authorized_user"
}`
	adcPath := filepath.Join(gcloudDir, "application_default_credentials.json")
	if err := os.WriteFile(adcPath, []byte(adcJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	if !config.HasADC() {
		t.Fatal("HasADC() = false after writing valid authorized_user ADC file, want true")
	}

	cmd := newTestCommand()
	val, source := config.ResolveRequestSecurityCredential(cmd, "access-token")
	if val != "ya29.adc-user-token" || source != "adc" {
		t.Fatalf("ResolveRequestSecurityCredential = (%q, %q), want (\"ya29.adc-user-token\", \"adc\")", val, source)
	}

	// Second call must hit the in-memory cache without another HTTP request.
	val2, source2 := config.ResolveRequestSecurityCredential(cmd, "access-token")
	if val2 != "ya29.adc-user-token" || source2 != "adc" {
		t.Fatalf("second ResolveRequestSecurityCredential = (%q, %q), want cached token", val2, source2)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("token endpoint hits = %d, want 1 (cached)", got)
	}
}

func TestADCServiceAccountScopesAndJWT(t *testing.T) {
	home := isolateADCEnv(t)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	var tokenServer *httptest.Server
	tokenServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q, want jwt-bearer", got)
		}
		assertion := r.Form.Get("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Fatalf("JWT parts = %d, want 3", len(parts))
		}
		claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode JWT claims: %v", err)
		}
		var claims struct {
			Iss   string `json:"iss"`
			Scope string `json:"scope"`
			Aud   string `json:"aud"`
		}
		if err := json.Unmarshal(claimsBytes, &claims); err != nil {
			t.Fatalf("unmarshal JWT claims: %v", err)
		}
		if claims.Iss != "svc-test@example.iam.gserviceaccount.com" {
			t.Errorf("JWT iss = %q, want svc-test@example.iam.gserviceaccount.com", claims.Iss)
		}
		wantScope := strings.Join(config.ADCScopes, " ")
		if claims.Scope != wantScope {
			t.Errorf("JWT scope = %q, want %q", claims.Scope, wantScope)
		}
		if claims.Aud != tokenServer.URL {
			t.Errorf("JWT aud = %q, want %q", claims.Aud, tokenServer.URL)
		}

		// Verify RSA-SHA256 signature.
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode JWT sig: %v", err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("JWT signature verification failed: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"ya29.sa-adc-token","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer tokenServer.Close()

	saFile := filepath.Join(home, "sa.json")
	saPayload, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "svc-test@example.iam.gserviceaccount.com",
		"private_key":  string(pemBytes),
		"token_uri":    tokenServer.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(saFile, saPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", saFile)

	cmd := newTestCommand()
	val, source := config.ResolveRequestSecurityCredential(cmd, "access-token")
	if val != "ya29.sa-adc-token" || source != "adc" {
		t.Fatalf("ResolveRequestSecurityCredential = (%q, %q), want (\"ya29.sa-adc-token\", \"adc\")", val, source)
	}
}

func TestADCPrecedenceAndDryRun(t *testing.T) {
	home := isolateADCEnv(t)

	var hits atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"ya29.adc-token","expires_in":3600}`)
	}))
	defer tokenServer.Close()

	saKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(saKey),
	})
	adcFile := filepath.Join(home, "adc.json")
	adcData, _ := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "sa@example.iam.gserviceaccount.com",
		"private_key":  string(pemBytes),
		"token_uri":    tokenServer.URL,
	})
	if err := os.WriteFile(adcFile, adcData, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", adcFile)

	// 1. --dry-run must NOT make network calls to exchange ADC tokens.
	dryCmd := newTestCommand()
	_ = dryCmd.PersistentFlags().Set("dry-run", "true")
	if val, source := config.ResolveRequestSecurityCredential(dryCmd, "access-token"); val != "" || source != "unset" {
		t.Fatalf("dry-run ResolveRequestSecurityCredential = (%q, %q), want (\"\", \"unset\")", val, source)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("dry-run made %d token endpoint calls, want 0", got)
	}

	// 2. When GEMINI_API_KEY is set, ResolveRequestSecurityCredential("access-token")
	// skips ADC network exchange because api-key outranks adc.
	t.Setenv("GEMINI_API_KEY", "env-api-key")
	cmd := newTestCommand()
	if val, source := config.ResolveRequestSecurityCredential(cmd, "access-token"); val != "" || source != "unset" {
		t.Fatalf("with GEMINI_API_KEY set, access-token = (%q, %q), want (\"\", \"unset\")", val, source)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("with GEMINI_API_KEY set, ADC made %d token endpoint calls, want 0", got)
	}
	t.Setenv("GEMINI_API_KEY", "")

	// 3. Source rank order: flag (0) < env (1) < keyring (2) < config (3) < adc (4) < unset (5).
	if config.CredentialSourceRank("config") >= config.CredentialSourceRank("adc") {
		t.Errorf("rank(config)=%d >= rank(adc)=%d, want config < adc",
			config.CredentialSourceRank("config"), config.CredentialSourceRank("adc"))
	}
	if config.CredentialSourceRank("adc") >= config.CredentialSourceRank("unset") {
		t.Errorf("rank(adc)=%d >= rank(unset)=%d, want adc < unset",
			config.CredentialSourceRank("adc"), config.CredentialSourceRank("unset"))
	}
}
