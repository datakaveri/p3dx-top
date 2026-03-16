package services

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestExtractProviderContext tests the provider context extraction
func TestExtractProviderContext(t *testing.T) {
	tests := []struct {
		name         string
		contract     map[string]interface{}
		wantProvider string
		wantPolicy   string
		wantAction   string
	}{
		{
			name: "contract with top-level fields",
			contract: map[string]interface{}{
				"provider_id": "provider1",
				"policy_id":   "policy1",
				"action":      "read",
			},
			wantProvider: "provider1",
			wantPolicy:   "policy1",
			wantAction:   "read",
		},
		{
			name: "contract with alternative field names",
			contract: map[string]interface{}{
				"data_provider_id":        "provider2",
				"data_provider_policy_id": "policy2",
				"operation":               "write",
			},
			wantProvider: "provider2",
			wantPolicy:   "policy2",
			wantAction:   "write",
		},
		{
			name: "contract with nested provider object",
			contract: map[string]interface{}{
				"provider": map[string]interface{}{
					"id":        "provider3",
					"policy_id": "policy3",
					"action":    "delete",
				},
			},
			wantProvider: "provider3",
			wantPolicy:   "policy3",
			wantAction:   "delete",
		},
		{
			name: "contract with dataProvider nested object",
			contract: map[string]interface{}{
				"dataProvider": map[string]interface{}{
					"provider_id": "provider4",
				},
			},
			wantProvider: "provider4",
			wantPolicy:   "",
			wantAction:   "",
		},
		{
			name:         "empty contract",
			contract:     map[string]interface{}{},
			wantProvider: "",
			wantPolicy:   "",
			wantAction:   "",
		},
		{
			name: "contract with purpose instead of action",
			contract: map[string]interface{}{
				"source":  "provider5",
				"purpose": "analysis",
			},
			wantProvider: "",
			wantPolicy:   "",
			wantAction:   "analysis",
		},
		{
			name: "partial contract",
			contract: map[string]interface{}{
				"provider_id": "provider6",
				"action":      "execute",
			},
			wantProvider: "provider6",
			wantPolicy:   "",
			wantAction:   "execute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, policy, action := extractProviderContext(tt.contract)

			if provider != tt.wantProvider {
				t.Errorf("provider = %q, want %q", provider, tt.wantProvider)
			}
			if policy != tt.wantPolicy {
				t.Errorf("policy = %q, want %q", policy, tt.wantPolicy)
			}
			if action != tt.wantAction {
				t.Errorf("action = %q, want %q", action, tt.wantAction)
			}
		})
	}
}

// TestBuildPolicyPaths tests policy path building
func TestBuildPolicyPaths(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		policyID   string
		template   string
		wantPaths  []string
	}{
		{
			name:       "with policy ID only",
			providerID: "provider1",
			policyID:   "policy1",
			template:   "",
			wantPaths:  []string{"/api/v1/policy/policy1", "/api/v1/policy/item/provider1"},
		},
		{
			name:       "with template",
			providerID: "provider2",
			policyID:   "policy2",
			template:   "/custom/{provider_id}/{policy_id}",
			wantPaths:  []string{"/custom/provider2/policy2"},
		},
		{
			name:       "template without leading slash",
			providerID: "provider3",
			policyID:   "policy3",
			template:   "api/policies/{policy_id}",
			wantPaths:  []string{"/api/policies/policy3"},
		},
		{
			name:       "empty provider and policy",
			providerID: "",
			policyID:   "",
			template:   "",
			wantPaths:  []string{},
		},
		{
			name:       "policy ID only",
			providerID: "",
			policyID:   "policy4",
			template:   "",
			wantPaths:  []string{"/api/v1/policy/policy4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.template != "" {
				t.Setenv("APD_POLICY_PATH_TEMPLATE", tt.template)
			} else {
				t.Setenv("APD_POLICY_PATH_TEMPLATE", "")
			}

			paths := buildPolicyPaths(tt.providerID, tt.policyID)

			if len(paths) != len(tt.wantPaths) {
				t.Errorf("buildPolicyPaths() returned %d paths, want %d", len(paths), len(tt.wantPaths))
			}

			for i, p := range paths {
				if i < len(tt.wantPaths) && p != tt.wantPaths[i] {
					t.Errorf("path[%d] = %q, want %q", i, p, tt.wantPaths[i])
				}
			}
		})
	}
}

// TestRawToStrings tests conversion of various types to string slices
func TestRawToStrings(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{
			name:  "nil",
			input: nil,
			want:  nil,
		},
		{
			name:  "single string",
			input: "value",
			want:  []string{"value"},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "interface slice with strings",
			input: []interface{}{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "interface slice with empty strings filtered",
			input: []interface{}{"a", "", "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "interface slice with mixed types",
			input: []interface{}{"a", 123, "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "string slice",
			input: []string{"x", "y", "z"},
			want:  []string{"x", "y", "z"},
		},
		{
			name:  "integer",
			input: 42,
			want:  nil,
		},
		{
			name:  "map",
			input: map[string]string{"key": "value"},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rawToStrings(tt.input)

			if len(result) != len(tt.want) {
				t.Errorf("rawToStrings() returned %d items, want %d", len(result), len(tt.want))
				return
			}

			for i, v := range result {
				if v != tt.want[i] {
					t.Errorf("rawToStrings()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

// TestStringSet tests string set creation
func TestStringSet(t *testing.T) {
	tests := []struct {
		name  string
		input [][]string
		want  map[string]struct{}
	}{
		{
			name:  "single group",
			input: [][]string{{"a", "b", "c"}},
			want:  map[string]struct{}{"a": {}, "b": {}, "c": {}},
		},
		{
			name:  "multiple groups",
			input: [][]string{{"a", "b"}, {"c", "d"}},
			want:  map[string]struct{}{"a": {}, "b": {}, "c": {}, "d": {}},
		},
		{
			name:  "duplicate values",
			input: [][]string{{"a", "b"}, {"b", "c"}},
			want:  map[string]struct{}{"a": {}, "b": {}, "c": {}},
		},
		{
			name:  "empty strings filtered",
			input: [][]string{{"a", "", "b"}},
			want:  map[string]struct{}{"a": {}, "b": {}},
		},
		{
			name:  "empty groups",
			input: [][]string{},
			want:  map[string]struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringSet(tt.input...)

			if len(result) != len(tt.want) {
				t.Errorf("stringSet() returned %d items, want %d", len(result), len(tt.want))
				return
			}

			for k := range tt.want {
				if _, ok := result[k]; !ok {
					t.Errorf("stringSet() missing key %q", k)
				}
			}
		})
	}
}

// TestHas tests set membership
func TestHas(t *testing.T) {
	set := map[string]struct{}{"a": {}, "b": {}, "c": {}}

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "existing value",
			value: "a",
			want:  true,
		},
		{
			name:  "non-existing value",
			value: "d",
			want:  false,
		},
		{
			name:  "empty string",
			value: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := has(set, tt.value)
			if result != tt.want {
				t.Errorf("has() = %v, want %v", result, tt.want)
			}
		})
	}
}

// TestIntersects tests set intersection
func TestIntersects(t *testing.T) {
	tests := []struct {
		name string
		a    map[string]struct{}
		b    map[string]struct{}
		want bool
	}{
		{
			name: "with common elements",
			a:    map[string]struct{}{"a": {}, "b": {}},
			b:    map[string]struct{}{"b": {}, "c": {}},
			want: true,
		},
		{
			name: "no common elements",
			a:    map[string]struct{}{"a": {}, "b": {}},
			b:    map[string]struct{}{"c": {}, "d": {}},
			want: false,
		},
		{
			name: "empty set a",
			a:    map[string]struct{}{},
			b:    map[string]struct{}{"a": {}},
			want: false,
		},
		{
			name: "empty set b",
			a:    map[string]struct{}{"a": {}},
			b:    map[string]struct{}{},
			want: false,
		},
		{
			name: "both empty",
			a:    map[string]struct{}{},
			b:    map[string]struct{}{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intersects(tt.a, tt.b)
			if result != tt.want {
				t.Errorf("intersects() = %v, want %v", result, tt.want)
			}
		})
	}
}

// TestContainsAll tests if a set contains all elements of another
func TestContainsAll(t *testing.T) {
	tests := []struct {
		name string
		have map[string]struct{}
		need map[string]struct{}
		want bool
	}{
		{
			name: "have all required",
			have: map[string]struct{}{"a": {}, "b": {}, "c": {}},
			need: map[string]struct{}{"a": {}, "b": {}},
			want: true,
		},
		{
			name: "missing required",
			have: map[string]struct{}{"a": {}},
			need: map[string]struct{}{"a": {}, "b": {}},
			want: false,
		},
		{
			name: "empty need",
			have: map[string]struct{}{"a": {}},
			need: map[string]struct{}{},
			want: true,
		},
		{
			name: "empty have",
			have: map[string]struct{}{},
			need: map[string]struct{}{"a": {}},
			want: false,
		},
		{
			name: "exact match",
			have: map[string]struct{}{"a": {}, "b": {}},
			need: map[string]struct{}{"a": {}, "b": {}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAll(tt.have, tt.need)
			if result != tt.want {
				t.Errorf("containsAll() = %v, want %v", result, tt.want)
			}
		})
	}
}

// TestUserIDsFromClaims tests extraction of user IDs from JWT claims
func TestUserIDsFromClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   map[string]struct{}
	}{
		{
			name: "with sub claim",
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			want: map[string]struct{}{"user123": {}},
		},
		{
			name: "with multiple ID fields",
			claims: jwt.MapClaims{
				"sub":                "user123",
				"preferred_username": "testuser",
				"email":              "test@example.com",
			},
			want: map[string]struct{}{"user123": {}, "testuser": {}, "test@example.com": {}},
		},
		{
			name: "with interface slice",
			claims: jwt.MapClaims{
				"sub": []interface{}{"user1", "user2"},
			},
			want: map[string]struct{}{"user1": {}, "user2": {}},
		},
		{
			name:   "empty claims",
			claims: jwt.MapClaims{},
			want:   map[string]struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := userIDsFromClaims(tt.claims)

			if len(result) != len(tt.want) {
				t.Errorf("userIDsFromClaims() returned %d items, want %d", len(result), len(tt.want))
				return
			}

			for k := range tt.want {
				if _, ok := result[k]; !ok {
					t.Errorf("userIDsFromClaims() missing key %q", k)
				}
			}
		})
	}
}

// TestRolesFromClaims tests extraction of roles from JWT claims
func TestRolesFromClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   map[string]struct{}
	}{
		{
			name: "with roles array",
			claims: jwt.MapClaims{
				"roles": []interface{}{"admin", "user"},
			},
			want: map[string]struct{}{"admin": {}, "user": {}},
		},
		{
			name: "with realm_access roles",
			claims: jwt.MapClaims{
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"realm-admin", "realm-user"},
				},
			},
			want: map[string]struct{}{"realm-admin": {}, "realm-user": {}},
		},
		{
			name: "with resource_access roles",
			claims: jwt.MapClaims{
				"resource_access": map[string]interface{}{
					"my-app": map[string]interface{}{
						"roles": []interface{}{"app-admin", "app-user"},
					},
				},
			},
			want: map[string]struct{}{"app-admin": {}, "app-user": {}},
		},
		{
			name: "with all role sources",
			claims: jwt.MapClaims{
				"roles": []interface{}{"user"},
				"realm_access": map[string]interface{}{
					"roles": []interface{}{"realm-user"},
				},
				"resource_access": map[string]interface{}{
					"app": map[string]interface{}{
						"roles": []interface{}{"app-user"},
					},
				},
			},
			want: map[string]struct{}{"user": {}, "realm-user": {}, "app-user": {}},
		},
		{
			name:   "empty claims",
			claims: jwt.MapClaims{},
			want:   map[string]struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rolesFromClaims(tt.claims)

			if len(result) != len(tt.want) {
				t.Errorf("rolesFromClaims() returned %d items, want %d", len(result), len(tt.want))
				return
			}

			for k := range tt.want {
				if _, ok := result[k]; !ok {
					t.Errorf("rolesFromClaims() missing key %q", k)
				}
			}
		})
	}
}

// TestScopesFromClaims tests extraction of scopes from JWT claims
func TestScopesFromClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   map[string]struct{}
	}{
		{
			name: "with scp array",
			claims: jwt.MapClaims{
				"scp": []interface{}{"read", "write"},
			},
			want: map[string]struct{}{"read": {}, "write": {}},
		},
		{
			name: "with scope space-separated string",
			claims: jwt.MapClaims{
				"scope": "read write delete",
			},
			want: map[string]struct{}{"read": {}, "write": {}, "delete": {}},
		},
		{
			name: "with both scp and scope",
			claims: jwt.MapClaims{
				"scp":   []interface{}{"profile"},
				"scope": "openid email",
			},
			want: map[string]struct{}{"profile": {}, "openid": {}, "email": {}},
		},
		{
			name:   "empty claims",
			claims: jwt.MapClaims{},
			want:   map[string]struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scopesFromClaims(tt.claims)

			if len(result) != len(tt.want) {
				t.Errorf("scopesFromClaims() returned %d items, want %d", len(result), len(tt.want))
				return
			}

			for k := range tt.want {
				if _, ok := result[k]; !ok {
					t.Errorf("scopesFromClaims() missing key %q", k)
				}
			}
		})
	}
}

// TestValuesByPath tests nested map path traversal
func TestValuesByPath(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		path string
		want []string
	}{
		{
			name: "simple path",
			m: map[string]interface{}{
				"field": "value",
			},
			path: "field",
			want: []string{"value"},
		},
		{
			name: "nested path",
			m: map[string]interface{}{
				"parent": map[string]interface{}{
					"child": "value",
				},
			},
			path: "parent.child",
			want: []string{"value"},
		},
		{
			name: "array value",
			m: map[string]interface{}{
				"items": []interface{}{"a", "b", "c"},
			},
			path: "items",
			want: []string{"a", "b", "c"},
		},
		{
			name: "non-existent path",
			m: map[string]interface{}{
				"field": "value",
			},
			path: "nonexistent",
			want: nil,
		},
		{
			name: "path with non-map intermediate",
			m: map[string]interface{}{
				"field": "value",
			},
			path: "field.nested",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := valuesByPath(tt.m, tt.path)

			if len(result) != len(tt.want) {
				t.Errorf("valuesByPath() returned %d items, want %d", len(result), len(tt.want))
				return
			}

			for i, v := range result {
				if v != tt.want[i] {
					t.Errorf("valuesByPath()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

// TestStringValue tests extraction of string values from maps
func TestStringValue(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]interface{}
		keys []string
		want string
	}{
		{
			name: "first key exists",
			m:    map[string]interface{}{"key1": "value1", "key2": "value2"},
			keys: []string{"key1", "key2"},
			want: "value1",
		},
		{
			name: "second key exists",
			m:    map[string]interface{}{"key2": "value2"},
			keys: []string{"key1", "key2"},
			want: "value2",
		},
		{
			name: "no keys exist",
			m:    map[string]interface{}{"key3": "value3"},
			keys: []string{"key1", "key2"},
			want: "",
		},
		{
			name: "non-string value",
			m:    map[string]interface{}{"key1": 123},
			keys: []string{"key1"},
			want: "",
		},
		{
			name: "empty string value",
			m:    map[string]interface{}{"key1": ""},
			keys: []string{"key1"},
			want: "",
		},
		{
			name: "empty map",
			m:    map[string]interface{}{},
			keys: []string{"key1"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringValue(tt.m, tt.keys...)
			if result != tt.want {
				t.Errorf("stringValue() = %q, want %q", result, tt.want)
			}
		})
	}
}
