package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestTenantMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid org from JWT claims", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		claims := &Claims{
			Sub:     "user-123",
			Email:   "user@test.com",
			OrgID:   uuid.New().String(),
			OrgSlug: "test-org",
			Roles:   []string{"admin"},
		}

		r.GET("/test", func(c *gin.Context) {
			c.Set("claims", claims)
			c.Next()
		}, TenantMiddleware(), func(c *gin.Context) {
			orgID, _ := c.Get("org_id")
			orgSlug, _ := c.Get("org_slug")
			if orgID == nil {
				t.Error("expected org_id to be set")
			}
			if orgSlug == nil {
				t.Error("expected org_slug to be set")
			}
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, c.Request)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
		}
	})

	t.Run("missing claims", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		r.GET("/test", TenantMiddleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, c.Request)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusUnauthorized, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "JWT claims not found") {
			t.Errorf("body = %s, want to contain 'JWT claims not found'", w.Body.String())
		}
	})

	t.Run("empty org_id in claims", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		claims := &Claims{
			Sub:     "user-123",
			Email:   "user@test.com",
			OrgID:   "",
			OrgSlug: "test-org",
			Roles:   []string{"admin"},
		}

		r.GET("/test", func(c *gin.Context) {
			c.Set("claims", claims)
			c.Next()
		}, TenantMiddleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, c.Request)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusUnauthorized, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "not associated with an organization") {
			t.Errorf("body = %s, want to contain 'not associated with an organization'", w.Body.String())
		}
	})
}

func TestGetOrgIDFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	orgID := uuid.New().String()

	t.Run("gin context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("org_id", orgID)

		got, err := GetOrgIDFromContext(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != orgID {
			t.Errorf("got %q, want %q", got, orgID)
		}
	})

	t.Run("stdlib context with ContextWithOrgID", func(t *testing.T) {
		ctx := ContextWithOrgID(context.Background(), uuid.MustParse(orgID))

		got, err := GetOrgIDFromContext(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != orgID {
			t.Errorf("got %q, want %q", got, orgID)
		}
	})

	t.Run("empty context", func(t *testing.T) {
		_, err := GetOrgIDFromContext(context.Background())
		if err == nil {
			t.Fatal("expected error for empty context")
		}
	})

	t.Run("unsupported context type", func(t *testing.T) {
		_, err := GetOrgIDFromContext(42)
		if err == nil {
			t.Fatal("expected error for unsupported type")
		}
	})

	t.Run("gin context without org_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		_, err := GetOrgIDFromContext(c)
		if err == nil {
			t.Fatal("expected error for missing org_id")
		}
	})

	t.Run("gin context with empty org_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("org_id", "")

		_, err := GetOrgIDFromContext(c)
		if err == nil {
			t.Fatal("expected error for empty org_id")
		}
	})
}

func TestParseOrgIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid org_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)
		orgUUID := uuid.New()

		r.GET("/test", func(c *gin.Context) {
			c.Set("org_id", orgUUID.String())
			c.Next()
		}, ParseOrgIDMiddleware(), func(c *gin.Context) {
			orgUUIDVal, exists := c.Get("org_uuid")
			if !exists {
				t.Fatal("expected org_uuid to be set")
			}
			parsed, ok := orgUUIDVal.(uuid.UUID)
			if !ok {
				t.Fatal("org_uuid is not a uuid.UUID")
			}
			if parsed != orgUUID {
				t.Errorf("got %v, want %v", parsed, orgUUID)
			}
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, c.Request)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
		}
	})

	t.Run("invalid uuid", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		r.GET("/test", func(c *gin.Context) {
			c.Set("org_id", "not-a-uuid")
			c.Next()
		}, ParseOrgIDMiddleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, c.Request)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusUnauthorized, w.Body.String())
		}
	})

	t.Run("missing org_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		r.GET("/test", ParseOrgIDMiddleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		c.Request = httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, c.Request)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusUnauthorized, w.Body.String())
		}
	})
}

func TestGetOrgUUIDFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		orgUUID := uuid.New()
		c.Set("org_uuid", orgUUID)

		got, err := GetOrgUUIDFromContext(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != orgUUID {
			t.Errorf("got %v, want %v", got, orgUUID)
		}
	})

	t.Run("missing", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		_, err := GetOrgUUIDFromContext(c)
		if err == nil {
			t.Fatal("expected error for missing org_uuid")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("org_uuid", "not-a-uuid")

		_, err := GetOrgUUIDFromContext(c)
		if err == nil {
			t.Fatal("expected error for invalid type")
		}
	})
}
