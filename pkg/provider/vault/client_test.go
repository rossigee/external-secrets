/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func TestNewConfig_ServerNameSet(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		expectName string
	}{
		{
			name:       "HTTPS URL with hostname",
			server:     "https://vault.example.com",
			expectName: "vault.example.com",
		},
		{
			name:       "HTTPS URL with hostname and port",
			server:     "https://vault.example.com:8200",
			expectName: "vault.example.com",
		},
		{
			name:       "HTTP URL (should still set ServerName)",
			server:     "http://vault.example.com",
			expectName: "vault.example.com",
		},
		{
			name:       "IP address",
			server:     "https://192.168.1.100:8200",
			expectName: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fake Kubernetes client
			fakeClient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-ca-bundle",
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						"ca.crt": testCACert,
					},
				},
			).Build()

			// Create client with CA provider
			c := &client{
				kube:      fakeClient,
				store: &esv1.VaultProvider{
					Server: tt.server,
					CAProvider: &esv1.CAProvider{
						Type: esv1.CAProviderTypeConfigMap,
						Name: "test-ca-bundle",
						Key:  "ca.crt",
					},
				},
				storeKind: esv1.SecretStoreKind,
				namespace: "test-namespace",
			}

			// Test newConfig
			cfg, err := c.newConfig(context.Background())
			require.NoError(t, err)
			require.NotNil(t, cfg)

			// Verify ServerName is set correctly
			if transport, ok := cfg.HttpClient.Transport.(*http.Transport); ok {
				assert.Equal(t, tt.expectName, transport.TLSClientConfig.ServerName,
					"ServerName should be set to hostname from server URL")
				assert.NotNil(t, transport.TLSClientConfig.RootCAs,
					"RootCAs should be set when CA provider is configured")
			} else {
				t.Fatal("Expected *http.Transport but got different type")
			}
		})
	}
}

func TestNewConfig_NoCAProvider_NoServerName(t *testing.T) {
	// Create client without CA provider
	c := &client{
		store: &esv1.VaultProvider{
			Server: "https://vault.example.com",
		},
		storeKind: esv1.SecretStoreKind,
		namespace: "test-namespace",
	}

	cfg, err := c.newConfig(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// When no CA provider is configured, ServerName should not be modified
	if transport, ok := cfg.HttpClient.Transport.(*http.Transport); ok {
		// Default vault.DefaultConfig() should handle ServerName through standard HTTP mechanisms
		assert.Nil(t, transport.TLSClientConfig.RootCAs,
			"RootCAs should be nil when no CA provider is configured")
	}
}

func TestNewConfig_InvalidURL(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithObjects(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-ca-bundle",
				Namespace: "test-namespace",
			},
			Data: map[string]string{
				"ca.crt": testCACert,
			},
		},
	).Build()

	// Test with invalid URL - should not fail, just not set ServerName
	c := &client{
		kube:      fakeClient,
		store: &esv1.VaultProvider{
			Server: "://invalid-url",
			CAProvider: &esv1.CAProvider{
				Type: esv1.CAProviderTypeConfigMap,
				Name: "test-ca-bundle",
				Key:  "ca.crt",
			},
		},
		storeKind: esv1.SecretStoreKind,
		namespace: "test-namespace",
	}

	cfg, err := c.newConfig(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Should still work, just without ServerName set
	if transport, ok := cfg.HttpClient.Transport.(*http.Transport); ok {
		assert.NotNil(t, transport.TLSClientConfig.RootCAs,
			"RootCAs should still be set even with invalid URL")
		// ServerName should be empty string (default) when URL parsing fails
		assert.Empty(t, transport.TLSClientConfig.ServerName,
			"ServerName should be empty when URL parsing fails")
	}
}

// testCACert is a valid CA certificate for testing
const testCACert = `-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----`