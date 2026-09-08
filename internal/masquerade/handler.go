package masquerade

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Handler implements HTTP masquerade server
type Handler struct {
	siteRoot   string
	rateLimits map[string][]time.Time
	rlMu       sync.Mutex
	rateLimit  int
	staticFS   http.FileSystem
}

// NewHandler creates a new masquerade handler
func NewHandler(siteRoot string, rateLimit int) (*Handler, error) {
	// If siteRoot doesn't exist, create minimal static site
	if _, err := os.Stat(siteRoot); os.IsNotExist(err) {
		if err := createMinimalSite(siteRoot); err != nil {
			return nil, fmt.Errorf("failed to create minimal site: %w", err)
		}
	}

	info, err := os.Stat(siteRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to stat site root: %w", err)
	}

	var staticFS http.FileSystem
	if info.IsDir() {
		staticFS = http.Dir(siteRoot)
	} else {
		// If it's a file, use its directory
		staticFS = http.Dir(filepath.Dir(siteRoot))
	}

	return &Handler{
		siteRoot:   siteRoot,
		rateLimits: make(map[string][]time.Time),
		rateLimit:  rateLimit,
		staticFS:   staticFS,
	}, nil
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Rate limiting
	clientIP := r.RemoteAddr
	if !h.checkRateLimit(clientIP) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("<html><body><h1>429 Too Many Requests</h1></body></html>"))
		return
	}

	// Path traversal protection
	if strings.Contains(r.URL.Path, "..") {
		w.Header().Set("Server", "nginx/1.25.3")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html><body><h1>403 Forbidden</h1></body></html>"))
		return
	}

	// Set common security headers
	w.Header().Set("Server", "nginx/1.25.3")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Keep-Alive", "timeout=5, max=100")

	// Handle different methods
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.serveStatic(w, r)
	case http.MethodOptions:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("<html><body><h1>405 Method Not Allowed</h1></body></html>"))
	}
}

func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}

	// Try to open the file
	f, err := h.staticFS.Open(path)
	if err != nil {
		// File not found - return nginx-style 404
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1><hr><em>nginx/1.25.3</em></center></body></html>`))
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if stat.IsDir() {
		// Try index.html in directory
		indexFile, err := h.staticFS.Open(path + "/index.html")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		defer indexFile.Close()
		f = indexFile
		stat, _ = indexFile.Stat()
	}

	// Generate ETag
	etag := h.generateETag(path, stat)
	w.Header().Set("ETag", etag)

	// Check If-None-Match
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	// Set content type
	contentType := h.getContentType(path)
	w.Header().Set("Content-Type", contentType)

	// ВАЖНО: не заявляем Content-Encoding: gzip, пока сжатие реально не
	// реализовано — клиенты попытались бы распаковать несжатый ответ.

	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
		w.WriteHeader(http.StatusOK)
		return
	}

	http.ServeContent(w, r, path, stat.ModTime(), f)
}

func (h *Handler) checkRateLimit(ip string) bool {
	h.rlMu.Lock()
	defer h.rlMu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Second)

	// Периодическая очистка забытых IP, чтобы map не рос бесконечно
	if len(h.rateLimits) > 4096 {
		for k, v := range h.rateLimits {
			if len(v) == 0 || v[len(v)-1].Before(windowStart) {
				delete(h.rateLimits, k)
			}
		}
	}

	// Filter old entries
	var recent []time.Time
	for _, t := range h.rateLimits[ip] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= h.rateLimit {
		h.rateLimits[ip] = recent
		return false
	}

	h.rateLimits[ip] = append(recent, now)
	return true
}

func (h *Handler) generateETag(path string, stat fs.FileInfo) string {
	hash := sha256.New()
	hash.Write([]byte(path))
	hash.Write([]byte(stat.ModTime().String()))
	hash.Write([]byte(fmt.Sprintf("%d", stat.Size())))
	return "\"" + hex.EncodeToString(hash.Sum(nil))[:16] + "\""
}

func (h *Handler) getContentType(path string) string {
	ext := filepath.Ext(strings.ToLower(path))
	switch ext {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".ico":
		return "image/x-icon"
	case ".svg":
		return "image/svg+xml"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	default:
		return "application/octet-stream"
	}
}

// createMinimalSite creates a minimal static website
func createMinimalSite(root string) error {
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}

	files := map[string]string{
		"index.html": `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <header>
        <h1>Welcome to Example Site</h1>
    </header>
    <main>
        <p>This is a sample static website.</p>
    </main>
    <script src="/app.js"></script>
</body>
</html>`,
		"style.css": `body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
header { background: #333; color: white; padding: 20px; border-radius: 5px; }
main { background: white; padding: 20px; margin-top: 20px; border-radius: 5px; }`,
		"app.js": `// Sample JavaScript
console.log('App loaded');
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM ready');
});`,
	}

	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}

	return nil
}
