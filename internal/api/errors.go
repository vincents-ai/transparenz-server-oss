// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	ErrTypeBase     = "about:blank"
	ErrUnauthorized = "https://datatracker.ietf.org/doc/html/rfc7235#section-3.1"
	ErrNotFound     = "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.4"
	ErrBadRequest   = "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.1"
	ErrInternal     = "about:blank"
)

// ProblemDetail represents an RFC 7807 problem detail response.
type ProblemDetail struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// RespondWithProblem writes an RFC 7807 problem detail response.
func RespondWithProblem(c *gin.Context, status int, problem ProblemDetail) {
	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(status, problem)
}

// BadRequest responds with a 400 Bad Request problem detail.
func BadRequest(c *gin.Context, detail string) {
	RespondWithProblem(c, http.StatusBadRequest, ProblemDetail{
		Type:   ErrBadRequest,
		Title:  "Bad Request",
		Status: http.StatusBadRequest,
		Detail: detail,
	})
}

// Unauthorized responds with a 401 Unauthorized problem detail.
func Unauthorized(c *gin.Context, detail string) {
	RespondWithProblem(c, http.StatusUnauthorized, ProblemDetail{
		Type:   ErrUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
		Detail: detail,
	})
}

// NotFound responds with a 404 Not Found problem detail.
func NotFound(c *gin.Context, detail string) {
	RespondWithProblem(c, http.StatusNotFound, ProblemDetail{
		Type:   ErrNotFound,
		Title:  "Not Found",
		Status: http.StatusNotFound,
		Detail: detail,
	})
}

// Forbidden responds with a 403 Forbidden problem detail.
func Forbidden(c *gin.Context, detail string) {
	RespondWithProblem(c, http.StatusForbidden, ProblemDetail{
		Type:   ErrTypeBase,
		Title:  "Forbidden",
		Status: http.StatusForbidden,
		Detail: detail,
	})
}

// InternalError responds with a 500 Internal Server Error problem detail.
func InternalError(c *gin.Context, detail string) {
	RespondWithProblem(c, http.StatusInternalServerError, ProblemDetail{
		Type:   ErrInternal,
		Title:  "Internal Server Error",
		Status: http.StatusInternalServerError,
		Detail: detail,
	})
}
