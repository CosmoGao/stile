package web

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/CosmoGao/stile/internal/auth"
	"github.com/CosmoGao/stile/internal/config"
	"github.com/CosmoGao/stile/internal/identity"
)

//go:embed templates/pages.html
var templateFS embed.FS

const (
	sessionCookie = "stile_session"
	csrfCookie    = "stile_csrf"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Server struct {
	cfg  config.Config
	db   *sql.DB
	auth *auth.Service
	tmpl *template.Template
	now  func() time.Time
}

type page struct {
	Title       string
	Error       string
	Notice      string
	CSRF        string
	User        *viewUser
	Users       []viewUser
	TOTPSecret  string
	TOTPURI     string
	TOTPEnabled bool
	TOTPPending bool
}

type viewUser struct {
	ID          string
	Username    string
	Admin       bool
	TOTPEnabled bool
	TOTPPending bool
	Disabled    bool
	Locked      bool
	LockedUntil string
	Self        bool
}

func New(cfg config.Config, db *sql.DB, key []byte) (*Server, error) {
	if cfg.LockoutFailures < 1 || cfg.LockoutDuration <= 0 || cfg.SessionTTL < time.Second {
		return nil, errors.New("lockout and session lifetime must be set from configuration")
	}
	if len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	tmpl, err := template.ParseFS(templateFS, "templates/pages.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:  cfg,
		db:   db,
		tmpl: tmpl,
		now:  time.Now,
	}
	s.auth = auth.New(db, key, cfg.SessionTTL, cfg.LockoutFailures, cfg.LockoutDuration, func() time.Time {
		return s.now()
	})
	return s, nil
}

// SetClock replaces the clock used for lockout and session expiry.
func (s *Server) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /setup", s.setupGet)
	mux.HandleFunc("POST /setup", s.setupPost)
	mux.HandleFunc("GET /login", s.loginGet)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /account/totp", s.totpGet)
	mux.HandleFunc("POST /account/totp/start", s.totpStart)
	mux.HandleFunc("POST /account/totp/confirm", s.totpConfirm)
	mux.HandleFunc("POST /account/totp/cancel", s.totpCancel)
	mux.HandleFunc("GET /admin/users", s.usersGet)
	mux.HandleFunc("POST /admin/users", s.usersCreate)
	mux.HandleFunc("POST /admin/users/{id}/disable", s.usersDisable)
	mux.HandleFunc("POST /admin/users/{id}/clear-lock", s.usersClearLock)
	mux.HandleFunc("POST /admin/users/{id}/clear-totp", s.usersClearTOTP)
	return mux
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data page) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
		http.Error(w, "页面错误", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) == 64 {
		return c.Value
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	val := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return val
}

func (s *Server) csrfOK(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	form := r.PostFormValue("csrf")
	if len(form) == 0 || len(form) != len(c.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(form), []byte(c.Value)) == 1
}

func (s *Server) postOK(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求无效", http.StatusBadRequest)
		return false
	}
	if !s.csrfOK(r) {
		http.Error(w, "请求无效", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) setSessionCookie(w http.ResponseWriter, raw []byte) {
	now := s.now()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    base64.RawURLEncoding.EncodeToString(raw),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  now.Add(s.cfg.SessionTTL),
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	})
}

func sessionRaw(r *http.Request) ([]byte, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(b) != 32 {
		return nil, errors.New("bad session cookie")
	}
	return b, nil
}

func (s *Server) currentUser(r *http.Request) (identity.User, bool) {
	raw, err := sessionRaw(r)
	if err != nil {
		return identity.User{}, false
	}
	u, err := s.auth.UserByToken(r.Context(), raw)
	if err != nil {
		return identity.User{}, false
	}
	return u, true
}

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (identity.User, bool) {
	u, ok := s.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return identity.User{}, false
	}
	return u, true
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (identity.User, bool) {
	u, ok := s.requireUser(w, r)
	if !ok {
		return identity.User{}, false
	}
	if u.Role != identity.RoleAdmin {
		http.Error(w, "没有权限", http.StatusForbidden)
		return identity.User{}, false
	}
	return u, true
}

func (s *Server) userCount(w http.ResponseWriter, r *http.Request) (int, bool) {
	n, err := identity.Count(r.Context(), s.db)
	if err != nil {
		log.Printf("count users: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return 0, false
	}
	return n, true
}

func (s *Server) view(u identity.User, selfID string) viewUser {
	v := viewUser{
		ID:          u.ID,
		Username:    u.Username,
		Admin:       u.Role == identity.RoleAdmin,
		TOTPEnabled: u.TOTPEnabled,
		TOTPPending: !u.TOTPEnabled && len(u.TOTPCiphertext) > 0,
		Disabled:    u.Disabled,
		Locked:      u.Locked(s.now()),
		Self:        u.ID == selfID,
	}
	if v.Locked && u.LockedUntil != nil {
		v.LockedUntil = u.LockedUntil.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return v
}

func noticeText(r *http.Request) string {
	switch r.URL.Query().Get("notice") {
	case "created":
		return "已创建普通用户"
	case "disabled":
		return "已停用"
	case "lock-cleared":
		return "已清除锁定"
	case "totp-cleared":
		return "已关闭二次验证"
	case "totp-enabled":
		return "已启用二次验证"
	default:
		return ""
	}
}

func loginMessage(err error) string {
	switch {
	case errors.Is(err, auth.ErrLocked):
		return "账号暂时不能登录"
	case errors.Is(err, auth.ErrDisabled):
		return "账号已停用"
	default:
		return "账号或口令不正确"
	}
}

func validID(id string) bool {
	return idPattern.MatchString(id)
}
