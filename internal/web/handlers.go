package web

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/CosmoGao/stile/internal/auth"
	"github.com/CosmoGao/stile/internal/identity"
)

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.currentUser(r); ok {
		vu := s.view(u, u.ID)
		s.render(w, http.StatusOK, "home", page{
			Title:  "首页",
			CSRF:   s.ensureCSRF(w, r),
			Notice: noticeText(r),
			User:   &vu,
		})
		return
	}
	n, ok := s.userCount(w, r)
	if !ok {
		return
	}
	if n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) setupGet(w http.ResponseWriter, r *http.Request) {
	n, ok := s.userCount(w, r)
	if !ok {
		return
	}
	if n > 0 {
		http.Error(w, "注册已关闭", http.StatusNotFound)
		return
	}
	s.render(w, http.StatusOK, "setup", page{
		Title: "创建管理员",
		CSRF:  s.ensureCSRF(w, r),
	})
}

func (s *Server) setupPost(w http.ResponseWriter, r *http.Request) {
	n, ok := s.userCount(w, r)
	if !ok {
		return
	}
	if n > 0 {
		http.Error(w, "注册已关闭", http.StatusNotFound)
		return
	}
	if !s.postOK(w, r) {
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	raw, _, err := s.auth.CreateFirstAdmin(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, identity.ErrSetupClosed) {
			http.Error(w, "注册已关闭", http.StatusNotFound)
			return
		}
		msg := "保存失败"
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, identity.ErrBadUsername):
			msg = "用户名无效"
		case errors.Is(err, auth.ErrBadPassword):
			msg = "请填写口令"
		default:
			log.Printf("setup: %v", err)
			status = http.StatusInternalServerError
			msg = "保存失败"
		}
		s.render(w, status, "setup", page{
			Title: "创建管理员",
			Error: msg,
			CSRF:  s.ensureCSRF(w, r),
		})
		return
	}
	s.setSessionCookie(w, raw)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	n, ok := s.userCount(w, r)
	if !ok {
		return
	}
	if n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", page{
		Title: "登录",
		CSRF:  s.ensureCSRF(w, r),
	})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	n, ok := s.userCount(w, r)
	if !ok {
		return
	}
	if n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if !s.postOK(w, r) {
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	code := strings.TrimSpace(r.PostFormValue("code"))
	raw, u, err := s.auth.Login(r.Context(), username, password, code)
	if err != nil {
		if !errors.Is(err, auth.ErrBadCredentials) && !errors.Is(err, auth.ErrLocked) && !errors.Is(err, auth.ErrDisabled) {
			log.Printf("login: %v", err)
			http.Error(w, "内部错误", http.StatusInternalServerError)
			return
		}
		s.render(w, http.StatusUnauthorized, "login", page{
			Title: "登录",
			Error: loginMessage(err),
			CSRF:  s.ensureCSRF(w, r),
		})
		return
	}
	_ = u
	s.setSessionCookie(w, raw)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.postOK(w, r) {
		return
	}
	if raw, err := sessionRaw(r); err == nil {
		if err := s.auth.Logout(r.Context(), raw); err != nil {
			log.Printf("logout: %v", err)
		}
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) totpGet(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	s.renderTOTP(w, r, u, http.StatusOK, "", "", "")
}

func (s *Server) totpStart(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	secret, uri, err := s.auth.BeginTOTP(r.Context(), u.ID)
	if err != nil {
		msg := "现在不能开始设置"
		if errors.Is(err, auth.ErrTOTPAlready) {
			msg = "二次验证已经启用"
		} else if !errors.Is(err, auth.ErrTOTPAlready) {
			log.Printf("totp start: %v", err)
			msg = "现在不能开始设置"
		}
		s.renderTOTP(w, r, u, http.StatusBadRequest, msg, "", "")
		return
	}
	fresh, err := identity.GetByID(r.Context(), s.db, u.ID)
	if err != nil {
		log.Printf("totp reload: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	s.renderTOTP(w, r, fresh, http.StatusOK, "", secret, uri)
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	err := s.auth.ConfirmTOTP(r.Context(), u.ID, strings.TrimSpace(r.PostFormValue("code")))
	if err != nil {
		msg := "验证码不正确"
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, auth.ErrTOTPCode):
			msg = "验证码不正确"
		case errors.Is(err, auth.ErrNoTOTP):
			msg = "还没有开始设置"
		case errors.Is(err, auth.ErrTOTPAlready):
			msg = "二次验证已经启用"
		default:
			log.Printf("totp confirm: %v", err)
			status = http.StatusInternalServerError
			msg = "保存失败"
		}
		fresh, gerr := identity.GetByID(r.Context(), s.db, u.ID)
		if gerr != nil {
			fresh = u
		}
		s.renderTOTP(w, r, fresh, status, msg, "", "")
		return
	}
	http.Redirect(w, r, "/account/totp?notice=totp-enabled", http.StatusSeeOther)
}

func (s *Server) totpCancel(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	if err := s.auth.CancelTOTP(r.Context(), u.ID); err != nil && !errors.Is(err, auth.ErrTOTPAlready) {
		log.Printf("totp cancel: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/account/totp", http.StatusSeeOther)
}

func (s *Server) renderTOTP(w http.ResponseWriter, r *http.Request, u identity.User, status int, msg, secret, uri string) {
	vu := s.view(u, u.ID)
	s.render(w, status, "totp", page{
		Title:       "二次验证",
		Error:       msg,
		Notice:      noticeText(r),
		CSRF:        s.ensureCSRF(w, r),
		User:        &vu,
		TOTPSecret:  secret,
		TOTPURI:     uri,
		TOTPEnabled: u.TOTPEnabled,
		TOTPPending: !u.TOTPEnabled && len(u.TOTPCiphertext) > 0,
	})
}

func (s *Server) usersGet(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, "")
}

func (s *Server) usersCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	err := s.auth.CreateUser(r.Context(), strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password"))
	if err != nil {
		msg := "保存失败"
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, identity.ErrBadUsername):
			msg = "用户名无效"
		case errors.Is(err, auth.ErrBadPassword):
			msg = "请填写口令"
		case errors.Is(err, identity.ErrDuplicate):
			msg = "用户名已存在"
		default:
			log.Printf("create user: %v", err)
			status = http.StatusInternalServerError
			msg = "保存失败"
		}
		s.renderUsers(w, r, status, msg)
		return
	}
	http.Redirect(w, r, "/admin/users?notice=created", http.StatusSeeOther)
}

func (s *Server) usersDisable(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	if id == u.ID {
		s.renderUsers(w, r, http.StatusBadRequest, "不能停用当前登录的管理员")
		return
	}
	if err := s.auth.DisableUser(r.Context(), id); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("disable user: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users?notice=disabled", http.StatusSeeOther)
}

func (s *Server) usersClearLock(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, "lock-cleared", func(id string) error {
		return s.auth.ClearLock(r.Context(), id)
	})
}

func (s *Server) usersClearTOTP(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, "totp-cleared", func(id string) error {
		return s.auth.ClearTOTP(r.Context(), id)
	})
}

func (s *Server) usersDelete(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	if id == u.ID {
		s.renderUsers(w, r, http.StatusBadRequest, "不能删除当前登录的用户")
		return
	}
	if err := identity.DeleteUser(r.Context(), s.db, id); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if errors.Is(err, identity.ErrLastAdmin) {
			s.renderUsers(w, r, http.StatusBadRequest, "不能删除仅有的管理员")
			return
		}
		log.Printf("delete user: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users?notice=user-deleted", http.StatusSeeOther)
}

func (s *Server) userAction(w http.ResponseWriter, r *http.Request, notice string, fn func(string) error) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	if err := fn(id); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("user action: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users?notice="+notice, http.StatusSeeOther)
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	list, err := identity.List(r.Context(), s.db)
	if err != nil {
		log.Printf("list users: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	views := make([]viewUser, 0, len(list))
	for _, item := range list {
		views = append(views, s.view(item, u.ID))
	}
	vu := s.view(u, u.ID)
	s.render(w, status, "users", page{
		Title:  "用户",
		Error:  msg,
		Notice: noticeText(r),
		CSRF:   s.ensureCSRF(w, r),
		User:   &vu,
		Users:  views,
	})
}
