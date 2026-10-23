package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CosmoGao/stile/internal/config"
)

// Cookie policy is explicit even when TLS terminates before the HTTP backend.
// Neither direct TLS nor untrusted forwarding headers may override it.
func TestCookiePolicyIgnoresTransportAndForwardedHeaders(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, target := range []string{"http://stile.test/", "https://stile.test/"} {
			for _, proto := range []string{"", "http", "https"} {
				t.Run(target+proto+map[bool]string{false: "/insecure", true: "/secure"}[secure], func(t *testing.T) {
					s := &Server{cfg: config.Config{CookieSecure: secure, SessionTTL: time.Hour}, now: time.Now}
					r := httptest.NewRequest(http.MethodGet, target, nil)
					r.Header.Set("X-Forwarded-Proto", proto)
					r.Header.Set("Forwarded", "proto="+proto)
					w := httptest.NewRecorder()
					s.ensureCSRF(w, r)
					s.setSessionCookie(w, make([]byte, 32))
					s.clearSessionCookie(w)
					cookies := w.Result().Cookies()
					if len(cookies) != 3 {
						t.Fatalf("cookie count = %d", len(cookies))
					}
					for _, ck := range cookies {
						if ck.Secure != secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
							t.Fatalf("unexpected cookie policy: %+v", ck)
						}
					}
					if cookies[0].Name != csrfCookie || cookies[1].Name != sessionCookie || cookies[2].Name != sessionCookie {
						t.Fatal("unexpected cookie names")
					}
					if cookies[2].MaxAge != -1 || cookies[2].Value != "" {
						t.Fatal("session was not cleared")
					}
				})
			}
		}
	}
}
