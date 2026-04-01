package porter_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/catgoose/porter"
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

func ExampleSessionSettingsMiddleware() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	handler := porter.SessionSettingsMiddleware(repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "theme=%s layout=%s", s.Theme, s.Layout)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// theme=light layout=classic
}

func ExampleSessionSettingsMiddleware_customConfig() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	cfg := porter.SessionConfig{
		CookieName: "my_app_session",
		Logger:     slog.Default(),
	}
	handler := porter.SessionSettingsMiddleware(repo, nil, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "theme=%s", s.Theme)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// theme=light
}

func ExampleSessionSettingsMiddleware_withIDFunc() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}

	// Use a custom function to extract the session ID from the request.
	idFunc := func(r *http.Request) string {
		return r.Header.Get("X-Session-ID")
	}
	handler := porter.SessionSettingsMiddleware(repo, idFunc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "uuid=%s theme=%s", s.SessionUUID, s.Theme)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Session-ID", "user-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Code)
	fmt.Println(rec.Body.String())
	// Output:
	// 200
	// uuid=user-123 theme=light
}

func ExampleGetSessionSettings() {
	repo := &memorySettingsRepo{store: make(map[string]*porter.SessionSettings)}
	handler := porter.SessionSettingsMiddleware(repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := porter.GetSessionSettings(r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(s.Theme))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Body.String())
	// Output:
	// light
}

func ExampleNewDefaultSettings() {
	s := porter.NewDefaultSettings("abc-123")
	fmt.Println(s.SessionUUID)
	fmt.Println(s.Theme)
	fmt.Println(s.Layout)
	fmt.Println(len(s.Extra))
	// Output:
	// abc-123
	// light
	// classic
	// 0
}

func ExampleSessionSettings_SetExtra() {
	s := porter.NewDefaultSettings("abc-123")
	s.SetExtra("sidebar_collapsed", "true")
	s.SetExtra("default_page_size", "25")

	fmt.Println(s.GetExtra("sidebar_collapsed"))
	fmt.Println(s.GetExtra("default_page_size"))
	fmt.Println(s.GetExtra("nonexistent"))
	// Output:
	// true
	// 25
	//
}

func ExampleSessionSettings_MarshalExtra() {
	s := porter.NewDefaultSettings("abc-123")
	s.SetExtra("lang", "en")

	data, _ := s.MarshalExtra()
	fmt.Println(data)
	// Output:
	// {"lang":"en"}
}

func ExampleSessionSettings_UnmarshalExtra() {
	s := porter.NewDefaultSettings("abc-123")
	_ = s.UnmarshalExtra(`{"lang":"fr","tz":"UTC"}`)

	fmt.Println(s.GetExtra("lang"))
	fmt.Println(s.GetExtra("tz"))
	// Output:
	// fr
	// UTC
}
