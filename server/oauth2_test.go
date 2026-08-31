package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func TestGetStringClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":                "user-123",
		"email":              "test@example.com",
		"preferred_username": "testuser",
		"position":           "Software Engineer",
		"job_title":          "DevOps Lead",
		"numeric_value":      42,
		"nil_value":          nil,
	}

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"existing string claim", "sub", "user-123"},
		{"existing email claim", "email", "test@example.com"},
		{"existing position claim", "position", "Software Engineer"},
		{"existing job_title claim", "job_title", "DevOps Lead"},
		{"non-existent claim", "missing", ""},
		{"numeric claim returns empty", "numeric_value", ""},
		{"nil claim returns empty", "nil_value", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringClaim(claims, tt.key)
			if result != tt.expected {
				t.Errorf("getStringClaim(%q) = %q, want %q", tt.key, result, tt.expected)
			}
		})
	}
}

func TestGetBoolClaim(t *testing.T) {
	claims := map[string]interface{}{
		"email_verified": true,
		"verified_str":   "true",
		"false_str":      "false",
		"numeric_value":  1,
	}

	tests := []struct {
		name     string
		key      string
		expected *bool
	}{
		{"bool true", "email_verified", model.NewPointer(true)},
		{"string true", "verified_str", model.NewPointer(true)},
		{"string false", "false_str", model.NewPointer(false)},
		{"missing claim", "missing", nil},
		{"empty key", "", nil},
		{"unexpected type", "numeric_value", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getBoolClaim(claims, tt.key)
			switch {
			case tt.expected == nil && got != nil:
				t.Errorf("getBoolClaim(%q) = %v, want nil", tt.key, *got)
			case tt.expected != nil && got == nil:
				t.Errorf("getBoolClaim(%q) = nil, want %v", tt.key, *tt.expected)
			case tt.expected != nil && got != nil && *got != *tt.expected:
				t.Errorf("getBoolClaim(%q) = %v, want %v", tt.key, *got, *tt.expected)
			}
		})
	}
}

func TestGenerateRandomKey(t *testing.T) {
	key1, err := generateRandomKey(16)
	if err != nil {
		t.Fatalf("generateRandomKey failed: %v", err)
	}

	if len(key1) != 32 { // 16 bytes = 32 hex characters
		t.Errorf("key length = %d, want 32", len(key1))
	}

	// Two keys should be different
	key2, err := generateRandomKey(16)
	if err != nil {
		t.Fatalf("generateRandomKey failed: %v", err)
	}

	if key1 == key2 {
		t.Error("Two generated keys should not be identical")
	}
}

func TestStateSignAndVerify(t *testing.T) {
	p := &Plugin{}
	p.encryptionKey = "test-encryption-key-1234567890abcdef"

	token := "test-state-token"
	signed := p.signState(token)

	// Should contain the token and a signature
	if signed == token {
		t.Error("Signed state should differ from raw token")
	}

	// Verification should succeed
	extracted, err := p.verifyAndExtractState(signed)
	if err != nil {
		t.Fatalf("verifyAndExtractState failed: %v", err)
	}
	if extracted != token {
		t.Errorf("extracted token = %q, want %q", extracted, token)
	}

	// Tampered state should fail
	_, err = p.verifyAndExtractState("tampered-token:invalidsignature")
	if err == nil {
		t.Error("Tampered state should fail verification")
	}

	// Malformed state should fail
	_, err = p.verifyAndExtractState("noseparator")
	if err == nil {
		t.Error("Malformed state should fail verification")
	}
}

func TestRenderPopupAuthComplete(t *testing.T) {
	p := &Plugin{}

	rec := httptest.NewRecorder()
	p.renderPopupAuthComplete(rec, "https://mm.example.com", "/team/channel")

	res := rec.Result()
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want it to contain no-store", cc)
	}

	body := rec.Body.String()

	// The target must be embedded as a safe JS string literal (json-encoded).
	if !strings.Contains(body, `var target = "https://mm.example.com/team/channel"`) {
		t.Errorf("body missing json-encoded target; got:\n%s", body)
	}
	// The popup hands control back to the opener and broadcasts via localStorage.
	if !strings.Contains(body, "window.opener") {
		t.Error("body should navigate window.opener")
	}
	if !strings.Contains(body, "mattermost_oidc_login") {
		t.Error("body should broadcast completion via localStorage key")
	}
}

// TestRenderPopupAuthCompleteNoScriptInjection ensures a return path crafted to
// break out of the <script> block is neutralised by the json/HTML escaping.
func TestRenderPopupAuthCompleteNoScriptInjection(t *testing.T) {
	p := &Plugin{}

	rec := httptest.NewRecorder()
	// A hostile-looking path (it would already be rejected upstream, but the render
	// must be safe regardless of what reaches it).
	p.renderPopupAuthComplete(rec, "https://mm.example.com", `/x</script><script>alert(1)</script>`)

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("unescaped </script> breakout present in body:\n%s", body)
	}
}

func TestStateCookieMatches(t *testing.T) {
	const token = "abc123deadbeef"

	newReq := func(cookieVal *string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/oauth2/callback", nil)
		if cookieVal != nil {
			r.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: *cookieVal})
		}
		return r
	}
	strp := func(s string) *string { return &s }

	tests := []struct {
		name   string
		cookie *string // nil = no cookie set
		want   bool
	}{
		{"matching cookie", strp(token), true},
		{"missing cookie", nil, false},
		{"empty cookie", strp(""), false},
		{"mismatched cookie", strp("wrong-token"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stateCookieMatches(newReq(tc.cookie), token); got != tc.want {
				t.Errorf("stateCookieMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUpdateUserIfChanged(t *testing.T) {
	t.Run("no changes", func(t *testing.T) {
		p := &Plugin{}
		user := &model.User{
			Id:        "user-1",
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Software Engineer",
		}
		info := &OIDCUserInfo{
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Software Engineer",
		}

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Position != "Software Engineer" {
			t.Errorf("Position = %q, want 'Software Engineer'", updated.Position)
		}
	})

	t.Run("position changed", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:        "user-1",
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Junior Developer",
		}
		info := &OIDCUserInfo{
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Senior Developer",
		}

		api.On("UpdateUser", mock.MatchedBy(func(u *model.User) bool {
			return u.Id == "user-1" && u.Position == "Senior Developer"
		})).Return(func(u *model.User) *model.User {
			return u
		}, nil)

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Position != "Senior Developer" {
			t.Errorf("Position = %q, want 'Senior Developer'", updated.Position)
		}
		api.AssertExpectations(t)
	})

	t.Run("empty position claim does not overwrite existing position", func(t *testing.T) {
		p := &Plugin{}
		user := &model.User{
			Id:        "user-1",
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "Product Manager",
		}
		info := &OIDCUserInfo{
			Email:     "user@example.com",
			FirstName: "John",
			LastName:  "Doe",
			Position:  "",
		}

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Position != "Product Manager" {
			t.Errorf("Position = %q, want 'Product Manager'", updated.Position)
		}
	})

	t.Run("all fields updated when changed", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:        "user-1",
			Email:     "old@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
			Position:  "OldPos",
		}
		info := &OIDCUserInfo{
			Email:     "new@example.com",
			FirstName: "NewFirst",
			LastName:  "NewLast",
			Position:  "NewPos",
		}

		api.On("UpdateUser", mock.MatchedBy(func(u *model.User) bool {
			return u.Email == "new@example.com" &&
				u.FirstName == "NewFirst" &&
				u.LastName == "NewLast" &&
				u.Position == "NewPos"
		})).Return(func(u *model.User) *model.User {
			return u
		}, nil)

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.Email != "new@example.com" || updated.FirstName != "NewFirst" || updated.LastName != "NewLast" || updated.Position != "NewPos" {
			t.Errorf("user fields not updated correctly: %+v", updated)
		}
		api.AssertExpectations(t)
	})

	t.Run("api update error propagates", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:       "user-1",
			Email:    "user@example.com",
			Position: "OldPos",
		}
		info := &OIDCUserInfo{
			Position: "NewPos",
		}

		api.On("UpdateUser", mock.Anything).Return(nil, model.NewAppError("UpdateUser", "test.error", nil, "failed to update", http.StatusInternalServerError))

		_, err := p.updateUserIfChanged(user, info)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to update user") {
			t.Errorf("error = %q, want containing 'failed to update user'", err.Error())
		}
		api.AssertExpectations(t)
	})

	t.Run("email verified revoked by provider", func(t *testing.T) {
		api := &plugintest.API{}
		p := &Plugin{}
		p.SetAPI(api)

		user := &model.User{
			Id:            "user-1",
			Email:         "user@example.com",
			EmailVerified: true,
		}
		info := &OIDCUserInfo{
			Email:         "user@example.com",
			EmailVerified: model.NewPointer(false),
		}

		api.On("UpdateUser", mock.MatchedBy(func(u *model.User) bool {
			return u.Id == "user-1" && !u.EmailVerified
		})).Return(func(u *model.User) *model.User {
			return u
		}, nil)

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if updated.EmailVerified {
			t.Error("EmailVerified should be false after provider downgrade")
		}
		api.AssertExpectations(t)
	})

	t.Run("nil email verified claim leaves user untouched", func(t *testing.T) {
		p := &Plugin{}
		user := &model.User{
			Id:            "user-1",
			Email:         "user@example.com",
			EmailVerified: true,
		}
		info := &OIDCUserInfo{
			Email:         "user@example.com",
			EmailVerified: nil,
		}

		updated, err := p.updateUserIfChanged(user, info)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !updated.EmailVerified {
			t.Error("EmailVerified should remain true when claim is absent")
		}
	})
}

func TestNonceMatches(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		got      string
		want     bool
	}{
		{"equal", "abc123", "abc123", true},
		{"mismatch", "abc123", "other", false},
		{"empty got", "abc123", "", false},
		{"empty expected", "", "abc123", false},
		{"both empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nonceMatches(tt.expected, tt.got); got != tt.want {
				t.Errorf("nonceMatches(%q, %q) = %v, want %v", tt.expected, tt.got, got, tt.want)
			}
		})
	}
}

func TestOAuthStatePKCENonceRoundTrip(t *testing.T) {
	orig := OAuthState{
		Token:        "tok",
		CreateAt:     1,
		ReturnTo:     "/",
		CodeVerifier: oauth2.GenerateVerifier(),
		Nonce:        "deadbeef",
	}
	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got OAuthState
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.CodeVerifier != orig.CodeVerifier || got.Nonce != orig.Nonce {
		t.Errorf("round-trip = %+v, want verifier/nonce from %+v", got, orig)
	}
}
