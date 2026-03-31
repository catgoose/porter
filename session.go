package porter

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

const settingsContextKey = "sessionSettings"

// SessionConfig holds session middleware configuration.
type SessionConfig struct {
	CookieName string       // defaults to "porter_session_id"
	Logger     *slog.Logger // defaults to slog.Default()
}

func (cfg SessionConfig) cookieName() string {
	if cfg.CookieName != "" {
		return cfg.CookieName
	}
	return "porter_session_id"
}

func (cfg SessionConfig) logger() *slog.Logger {
	if cfg.Logger != nil {
		return cfg.Logger
	}
	return slog.Default()
}

// SessionSettingsProvider is the subset of session-settings operations that
// the middleware needs: look up, create-or-update, and touch a row.
type SessionSettingsProvider interface {
	GetByUUID(ctx context.Context, uuid string) (*SessionSettings, error)
	Upsert(ctx context.Context, s *SessionSettings) error
	Touch(ctx context.Context, uuid string) error
}

// SessionIDFunc returns the session identifier for the current request.
// When nil, the middleware falls back to a random cookie-based session ID.
type SessionIDFunc func(c echo.Context) string

// SessionSettingsMiddleware loads per-session settings and stores them on the
// echo context. The session ID comes from idFunc (e.g. Crooner's SCS token).
// When idFunc is nil or returns an empty string, the middleware falls back to
// a random cookie-based session ID.
func SessionSettingsMiddleware(repo SessionSettingsProvider, idFunc SessionIDFunc, cfgs ...SessionConfig) echo.MiddlewareFunc {
	var cfg SessionConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			sessionID := ""
			if idFunc != nil {
				sessionID = idFunc(c)
			}
			if sessionID == "" {
				sessionID = getOrCreateSessionCookie(c, cfg.cookieName())
			}

			settings, err := repo.GetByUUID(ctx, sessionID)
			if err != nil {
				cfg.logger().ErrorContext(ctx, "Failed to load session settings", "error", err)
				settings = NewDefaultSettings(sessionID)
			}
			if settings == nil {
				settings = NewDefaultSettings(sessionID)
				if err := repo.Upsert(ctx, settings); err != nil {
					cfg.logger().ErrorContext(ctx, "Failed to create session settings", "error", err)
				}
			}

			if time.Since(settings.UpdatedAt) > 24*time.Hour {
				_ = repo.Touch(ctx, sessionID)
			}

			c.Set(settingsContextKey, settings)
			return next(c)
		}
	}
}

// GetSessionSettings returns the session settings from the echo context.
func GetSessionSettings(c echo.Context) *SessionSettings {
	if s, ok := c.Get(settingsContextKey).(*SessionSettings); ok {
		return s
	}
	return NewDefaultSettings("")
}

// getOrCreateSessionCookie reads the session cookie or creates a new random one.
func getOrCreateSessionCookie(c echo.Context, cookieName string) string {
	if cookie, err := c.Cookie(cookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	id := randomUUID()
	c.SetCookie(&http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return id
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
