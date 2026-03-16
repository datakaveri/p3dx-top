package config

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		setup    func()
		cleanup  func()
		expected string
	}{
		{
			name: "existing environment variable",
			key:  "TEST_VAR_EXISTS",
			setup: func() {
				os.Setenv("TEST_VAR_EXISTS", "test_value")
			},
			cleanup: func() {
				os.Unsetenv("TEST_VAR_EXISTS")
			},
			expected: "test_value",
		},
		{
			name: "non-existing environment variable",
			key:  "TEST_VAR_NOT_EXISTS_12345",
			setup: func() {
				os.Unsetenv("TEST_VAR_NOT_EXISTS_12345")
			},
			cleanup:  func() {},
			expected: "",
		},
		{
			name: "empty string value",
			key:  "TEST_VAR_EMPTY",
			setup: func() {
				os.Setenv("TEST_VAR_EMPTY", "")
			},
			cleanup: func() {
				os.Unsetenv("TEST_VAR_EMPTY")
			},
			expected: "",
		},
		{
			name: "variable with special characters",
			key:  "TEST_VAR_SPECIAL",
			setup: func() {
				os.Setenv("TEST_VAR_SPECIAL", "value!@#$%^&*()")
			},
			cleanup: func() {
				os.Unsetenv("TEST_VAR_SPECIAL")
			},
			expected: "value!@#$%^&*()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			defer tt.cleanup()

			result := GetEnv(tt.key)
			if result != tt.expected {
				t.Errorf("GetEnv(%q) = %q, want %q", tt.key, result, tt.expected)
			}
		})
	}
}
