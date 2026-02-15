package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    bool
		errMessage string
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
			wantErr: false,
		},
		{
			name: "missing authorization header",
			headers: http.Header{
				"Authorization": []string{},
			},
			wantErr:    true,
			errMessage: "no authorization header included",
		},
		{
			name: "wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name: "missing API key part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
					return
				}
				if tt.errMessage != "" && err.Error() != tt.errMessage {
					t.Errorf("expected error %q, got %q", tt.errMessage, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
