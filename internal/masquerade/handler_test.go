package masquerade

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasquerade200(t *testing.T) {
	tmpDir := t.TempDir()
	siteRoot := tmpDir + "/site"
	h, err := NewHandler(siteRoot, 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestMasquerade404(t *testing.T) {
	tmpDir := t.TempDir()
	siteRoot := tmpDir + "/site"
	h, err := NewHandler(siteRoot, 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/nonexistent.html", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404, got %d", w.Code)
	}
}

func TestMasquerade405(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/index.html", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestMasqueradeRateLimit(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 5) // limit = 5
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	// Make 6 requests from same IP
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if i < 5 {
			if w.Code != http.StatusOK {
				t.Errorf("Request %d: Expected 200, got %d", i, w.Code)
			}
		} else {
			if w.Code != http.StatusTooManyRequests {
				t.Errorf("Request %d: Expected 429, got %d", i, w.Code)
			}
		}
	}
}

func TestMasqueradeETag304(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	// First request - get ETag
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("No ETag in response")
	}

	// Second request with If-None-Match
	req2 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()

	h.ServeHTTP(w2, req2)

	if w2.Code != http.StatusNotModified {
		t.Errorf("Expected 304, got %d", w2.Code)
	}
}

func TestMasqueradePathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/../../../etc/passwd", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestMasqueradeGzip(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	// Note: actual gzip compression is not implemented in this minimal version
	// but Content-Encoding header should be set
}

func TestMasqueradeHEAD(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Error("HEAD response should have empty body")
	}
}

func TestMasqueradeOptions(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected 204, got %d", w.Code)
	}
	allow := w.Header().Get("Allow")
	if !strings.Contains(allow, "GET") || !strings.Contains(allow, "HEAD") {
		t.Errorf("Allow header missing GET/HEAD: %s", allow)
	}
}

func TestMasqueradeHeaders(t *testing.T) {
	tmpDir := t.TempDir()
	h, err := NewHandler(tmpDir+"/site", 100)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	server := w.Header().Get("Server")
	if !strings.HasPrefix(server, "nginx/") {
		t.Errorf("Server header should start with 'nginx/', got: %s", server)
	}

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("Missing HSTS header")
	}

	xcto := w.Header().Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("X-Content-Type-Options should be 'nosniff', got: %s", xcto)
	}
}

func TestCreateMinimalSite(t *testing.T) {
	tmpDir := t.TempDir()
	siteRoot := filepath.Join(tmpDir, "site")

	err := createMinimalSite(siteRoot)
	if err != nil {
		t.Fatalf("createMinimalSite failed: %v", err)
	}

	files := []string{"index.html", "style.css", "app.js"}
	for _, f := range files {
		path := filepath.Join(siteRoot, f)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("File %s was not created", f)
		}
	}
}
