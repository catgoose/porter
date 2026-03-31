package porter_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/catgoose/porter"
	"github.com/labstack/echo/v4"
)

// memorySettingsRepo is a minimal in-memory SessionSettingsProvider for examples.
type memorySettingsRepo struct {
	store map[string]*porter.SessionSettings
}

func (m *memorySettingsRepo) GetByUUID(_ context.Context, uuid string) (*porter.SessionSettings, error) {
	s, ok := m.store[uuid]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *memorySettingsRepo) Upsert(_ context.Context, s *porter.SessionSettings) error {
	m.store[s.SessionUUID] = s
	return nil
}

func (m *memorySettingsRepo) Touch(_ context.Context, uuid string) error {
	return nil
}

// memoryCSRFStore is a minimal in-memory CSRFSessionStore for examples.
type memoryCSRFStore struct {
	data map[string]any
}

func (m *memoryCSRFStore) Get(_ echo.Context, key string) (any, error) {
	return m.data[key], nil
}

func (m *memoryCSRFStore) Set(_ echo.Context, key string, value any) error {
	m.data[key] = value
	return nil
}

func ExampleCSRF() {
	e := echo.New()

	store := &memoryCSRFStore{data: make(map[string]any)}
	e.Use(porter.CSRF(store, porter.CSRFConfig{}))
	e.GET("/", func(c echo.Context) error {
		token := c.Get("csrf_token").(string)
		return c.String(http.StatusOK, fmt.Sprintf("token_length=%d", len(token)))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// token_length=64
}

func ExampleCSRF_exemptPaths() {
	e := echo.New()

	store := &memoryCSRFStore{data: make(map[string]any)}
	e.Use(porter.CSRF(store, porter.CSRFConfig{
		ExemptPaths: []string{"/webhook"},
	}))
	e.POST("/webhook", func(c echo.Context) error {
		return c.String(http.StatusOK, "accepted")
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// accepted
}

func ExampleCSRF_nilStore() {
	e := echo.New()

	// Passing nil disables CSRF — useful in development or testing.
	e.Use(porter.CSRF(nil, porter.CSRFConfig{}))
	e.POST("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "no csrf")
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// no csrf
}

func ExampleCookieCSRFStore() {
	e := echo.New()

	e.Use(porter.CSRF(porter.CookieCSRFStore{}, porter.CSRFConfig{}))
	e.GET("/", func(c echo.Context) error {
		token := c.Get("csrf_token").(string)
		return c.String(http.StatusOK, fmt.Sprintf("token_length=%d", len(token)))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// token_length=64
}

func ExampleSessionSettingsMiddleware() {
	e := echo.New()

	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	e.Use(porter.SessionSettingsMiddleware(repo, nil))
	e.GET("/", func(c echo.Context) error {
		s := porter.GetSessionSettings(c)
		return c.String(http.StatusOK, fmt.Sprintf("theme=%s layout=%s", s.Theme, s.Layout))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// theme=light layout=classic
}

func ExampleSessionSettingsMiddleware_customConfig() {
	e := echo.New()

	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	cfg := porter.SessionConfig{
		CookieName: "my_app_session",
		Logger:     slog.Default(),
	}
	e.Use(porter.SessionSettingsMiddleware(repo, nil, cfg))
	e.GET("/", func(c echo.Context) error {
		s := porter.GetSessionSettings(c)
		return c.String(http.StatusOK, fmt.Sprintf("theme=%s", s.Theme))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// theme=light
}

func ExampleSessionSettingsMiddleware_withIDFunc() {
	e := echo.New()

	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}

	// Use a custom function to extract the session ID from the request.
	idFunc := func(c echo.Context) string {
		return c.Request().Header.Get("X-Session-ID")
	}
	e.Use(porter.SessionSettingsMiddleware(repo, idFunc))
	e.GET("/", func(c echo.Context) error {
		s := porter.GetSessionSettings(c)
		return c.String(http.StatusOK, fmt.Sprintf("uuid=%s theme=%s", s.SessionUUID, s.Theme))
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Session-ID", "user-123")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// uuid=user-123 theme=light
}

func ExampleGetSessionSettings() {
	e := echo.New()

	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	e.Use(porter.SessionSettingsMiddleware(repo, nil))
	e.GET("/", func(c echo.Context) error {
		s := porter.GetSessionSettings(c)
		return c.String(http.StatusOK, s.Theme)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	fmt.Println(rec.Body.String())
	// Output:
	// light
}

func ExampleNewDefaultSettings() {
	s := porter.NewDefaultSettings("abc-123")
	fmt.Println(s.SessionUUID)
	fmt.Println(s.Theme)
	fmt.Println(s.Layout)
	// Output:
	// abc-123
	// light
	// classic
}
