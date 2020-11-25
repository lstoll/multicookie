package multicookie

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/securecookie"
)

const testStoreName = "test"

var testKey = securecookie.GenerateRandomKey(32)

// Test for GH-8 for CookieStore
func TestMulticookie(t *testing.T) {
	store := New(testKey)

	req, err := http.NewRequest("GET", "http://www.example.com", nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	session, err := store.New(req, testStoreName)
	if err != nil {
		t.Fatal("failed to create session", err)
	}

	session.Values["a"] = 1
	session.Values["b"] = 2

	w := httptest.NewRecorder()

	if err := session.Save(req, w); err != nil {
		t.Fatalf("saving session: %v", err)
	}

	req, err = http.NewRequest("GET", "http://www.example.com", nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	t.Logf("cookies: %#v", w.Result().Cookies())

	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}

	session, err = store.Get(req, testStoreName)
	if err != nil {
		t.Fatal("failed to get session", err)
	}

	va, ok := session.Values["a"].(int)
	if !ok || va != 1 {
		t.Errorf("want val a = 1, got: %v (%t)", va, ok)
	}

	vb, ok := session.Values["b"].(int)
	if !ok || vb != 2 {
		t.Errorf("want val b = 2, got: %v (%t)", vb, ok)
	}
}
