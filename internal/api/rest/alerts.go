package rest

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vincents-ai/transparenz-server-oss/internal/api"
	"github.com/vincents-ai/transparenz-server-oss/pkg/middleware"
	"github.com/vincents-ai/transparenz-server-oss/pkg/services"
)

var (
	sseConnections sync.Map

	activeSSEConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sse_connections_active",
		Help: "Number of active SSE connections",
	})
)

func init() {
	prometheus.MustRegister(activeSSEConnections)
}

// AlertHandler handles server-sent event alert streams for organizations.
type AlertHandler struct {
	hub       *services.AlertHub
	jwtSecret string
}

// NewAlertHandler creates a handler for SSE alert streaming.
func NewAlertHandler(hub *services.AlertHub, jwtSecret string) *AlertHandler {
	return &AlertHandler{
		hub:       hub,
		jwtSecret: jwtSecret,
	}
}

func (h *AlertHandler) StreamAlerts(c *gin.Context) {
	orgUUID, err := middleware.GetOrgUUIDFromContext(c)
	if err != nil {
		api.Unauthorized(c, "organization context not available")
		return
	}
	orgID := orgUUID.String()

	token := c.Query("token")
	if token == "" {
		api.BadRequest(c, "token is required")
		return
	}

	if !h.validateToken(orgID, token) {
		api.Unauthorized(c, "invalid token")
		return
	}

	var connCount int
	if existing, ok := sseConnections.Load(orgID); ok {
		connCount = existing.(int)
	}
	if connCount >= 10 {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"type": "about:blank", "title": "Too Many Requests", "status": 429,
			"detail": "maximum SSE connections reached for this organization",
		})
		return
	}
	sseConnections.Store(orgID, connCount+1)
	activeSSEConnections.Inc()
	defer func() {
		activeSSEConnections.Dec()
		if current, ok := sseConnections.Load(orgID); ok {
			if current.(int) <= 1 {
				sseConnections.Delete(orgID)
			} else {
				sseConnections.Store(orgID, current.(int)-1)
			}
		}
	}()

	alerts, unsubscribe := h.hub.Subscribe(orgID)
	defer unsubscribe()

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	c.Stream(func(w io.Writer) bool {
		select {
		case alert, ok := <-alerts:
			if !ok {
				return false
			}
			c.SSEvent(alert.Type, alert)
			c.Writer.Flush()
			return true
		case <-c.Request.Context().Done():
			return false
		}
	})
}

func (h *AlertHandler) validateToken(orgID, tokenString string) bool {
	token, err := jwt.ParseWithClaims(tokenString, &middleware.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(h.jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return false
	}

	claims, ok := token.Claims.(*middleware.Claims)
	if !ok {
		return false
	}

	// Reject tokens that don't have an org_id (e.g. refresh tokens)
	if claims.OrgID == "" {
		return false
	}

	return claims.OrgID == orgID && strings.TrimSpace(claims.OrgID) != ""
}
