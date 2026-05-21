package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const testJWTSecret = "test-secret-key-for-testing"

func TestJWTMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		setupAuth  func() string
		wantStatus int
		wantError  string
		checkClaim bool
	}{
		{
			name: "valid token",
			setupAuth: func() string {
				return "Bearer " + generateTestToken(time.Now().Add(1*time.Hour))
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "expired token",
			setupAuth: func() string {
				return "Bearer " + generateTestToken(time.Now().Add(-1*time.Hour))
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "expired",
		},
		{
			name: "invalid token",
			setupAuth: func() string {
				return "Bearer garbage.invalid.token"
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "Invalid token",
		},
		{
			name: "missing header",
			setupAuth: func() string {
				return ""
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "Authorization header is required",
		},
		{
			name: "malformed bearer format",
			setupAuth: func() string {
				return "Token sometoken"
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "format: Bearer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, r := gin.CreateTestContext(w)
			r.GET("/test", JWTMiddleware(testJWTSecret), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			auth := tt.setupAuth()
			if auth != "" {
				c.Request = httptest.NewRequest("GET", "/test", nil)
				c.Request.Header.Set("Authorization", auth)
			} else {
				c.Request = httptest.NewRequest("GET", "/test", nil)
			}

			r.ServeHTTP(w, c.Request)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantError != "" && !strings.Contains(w.Body.String(), tt.wantError) {
				t.Errorf("body = %s, want to contain %q", w.Body.String(), tt.wantError)
			}
		})
	}
}

func generateTestToken(expiry time.Time) string {
	claims := jwt.MapClaims{
		"sub":      "user-123",
		"email":    "test@example.com",
		"org_id":   "org-456",
		"org_slug": "test-org",
		"roles":    []string{"admin"},
		"exp":      expiry.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString([]byte(testJWTSecret))
	return s
}

func TestGetClaimsFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid claims", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		expected := &Claims{
			Sub:     "sub-123",
			Email:   "user@test.com",
			OrgID:   "org-789",
			OrgSlug: "my-org",
			Roles:   []string{"compliance_officer"},
		}
		c.Set("claims", expected)

		got, err := GetClaimsFromContext(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Sub != expected.Sub {
			t.Errorf("Sub = %q, want %q", got.Sub, expected.Sub)
		}
		if got.Email != expected.Email {
			t.Errorf("Email = %q, want %q", got.Email, expected.Email)
		}
		if got.OrgID != expected.OrgID {
			t.Errorf("OrgID = %q, want %q", got.OrgID, expected.OrgID)
		}
		if got.OrgSlug != expected.OrgSlug {
			t.Errorf("OrgSlug = %q, want %q", got.OrgSlug, expected.OrgSlug)
		}
		if len(got.Roles) != len(expected.Roles) {
			t.Errorf("Roles = %v, want %v", got.Roles, expected.Roles)
		}
	})

	t.Run("missing claims", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		_, err := GetClaimsFromContext(c)
		if err == nil {
			t.Fatal("expected error for missing claims")
		}
	})

	t.Run("invalid claims type", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("claims", "not-a-claims-struct")

		_, err := GetClaimsFromContext(c)
		if err == nil {
			t.Fatal("expected error for invalid claims type")
		}
	})

	t.Run("JWTMiddleware sets claims on context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		var capturedClaims *Claims
		r.GET("/test", JWTMiddleware(testJWTSecret), func(c *gin.Context) {
			claims, err := GetClaimsFromContext(c)
			if err != nil {
				t.Fatalf("GetClaimsFromContext failed: %v", err)
			}
			capturedClaims = claims
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("Authorization", "Bearer "+generateTestToken(time.Now().Add(1*time.Hour)))
		r.ServeHTTP(w, c.Request)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		if capturedClaims.Sub != "user-123" {
			t.Errorf("Sub = %q, want %q", capturedClaims.Sub, "user-123")
		}
		if capturedClaims.Email != "test@example.com" {
			t.Errorf("Email = %q, want %q", capturedClaims.Email, "test@example.com")
		}
		if capturedClaims.OrgID != "org-456" {
			t.Errorf("OrgID = %q, want %q", capturedClaims.OrgID, "org-456")
		}
	})
}

func TestJWTMiddleware_ErrorResponseFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("missing header returns JSON error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)
		r.GET("/test", JWTMiddleware(testJWTSecret), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, c.Request)

		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
			t.Errorf("Content-Type = %q, want application/problem+json", ct)
		}

		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to parse response body: %v", err)
		}
		if body["detail"] == nil || body["detail"] == "" {
			t.Error("expected 'detail' field in response body")
		}
	})
}
