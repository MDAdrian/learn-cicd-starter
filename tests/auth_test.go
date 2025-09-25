package test

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("no authorization header", func(t *testing.T) {
		headers := http.Header{}
		_, err := auth.GetAPIKey(headers)
		if err != auth.ErrNoAuthHeaderIncluded {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("malformed authorization header - missing ApiKey prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer somekey")
		_, err := auth.GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("malformed authorization header - no key provided", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")
		_, err := auth.GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("valid authorization header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey secret123")
		key, err := auth.GetAPIKey(headers)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if key != "secret123" {
			t.Errorf("expected secret123, got %s", key)
		}
	})
}
