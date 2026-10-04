package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/CosmoGao/stile/internal/asset"
	"github.com/CosmoGao/stile/internal/credential"
	"github.com/CosmoGao/stile/internal/sshproxy"
)

func (s *Server) assetProbe(w http.ResponseWriter, r *http.Request) {
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
	item, err := s.assets.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("probe asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	if item.Protocol != asset.ProtocolSSH {
		s.renderAssets(w, r, http.StatusBadRequest, "只有 SSH 资产可以读取主机密钥")
		return
	}
	// TCP and SSH key exchange only. Credentials are not loaded.
	fingerprint, err := sshproxy.Probe(r.Context(), item.Host, item.Port)
	if err != nil {
		log.Printf("probe asset %s failed", id)
		s.renderAssets(w, r, http.StatusBadGateway, "没有读到主机密钥")
		return
	}
	view := userAssetView(item.ForUser())
	vu := s.view(u, u.ID)
	s.render(w, http.StatusOK, "probe", page{
		Title:  "主机密钥指纹",
		CSRF:   s.ensureCSRF(w, r),
		User:   &vu,
		Open:   &view,
		Probed: fingerprint,
	})
}

func (s *Server) assetHostKey(w http.ResponseWriter, r *http.Request) {
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
	err := s.assets.SetHostKeyFingerprint(r.Context(), id, r.PostFormValue("ssh_host_key_fingerprint"))
	if err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if errors.Is(err, asset.ErrBadInput) {
			s.renderAssets(w, r, http.StatusBadRequest, "指纹无效")
			return
		}
		log.Printf("save host key: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/assets?notice=hostkey-saved", http.StatusSeeOther)
}

// sshSocket is the same-origin terminal socket. The login cookie is sent by
// the browser. The page script does not receive the token, the password, or
// the private key.
func (s *Server) sshSocket(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	if _, err := s.assets.GetUser(r.Context(), id); err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("ssh asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	allowed, err := s.grants.Allowed(r.Context(), u.ID, id)
	if err != nil {
		log.Printf("ssh grant: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, openDenied, http.StatusForbidden)
		return
	}
	item, err := s.assets.Get(r.Context(), id)
	if err != nil {
		log.Printf("ssh asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	if item.Protocol != asset.ProtocolSSH {
		http.Error(w, "协议不是 SSH，不连接", http.StatusForbidden)
		return
	}
	if item.CredentialID == "" {
		http.Error(w, "未绑定凭据，打不开", http.StatusConflict)
		return
	}
	if item.HostKeyFingerprint == "" {
		http.Error(w, "还没有登记主机密钥指纹，不连接", http.StatusConflict)
		return
	}
	meta, err := s.creds.Lookup(r.Context(), item.CredentialID)
	if err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			http.Error(w, "未绑定凭据，打不开", http.StatusConflict)
			return
		}
		log.Printf("ssh credential: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	target := sshproxy.Target{
		Host:        item.Host,
		Port:        item.Port,
		User:        meta.LoginName,
		Fingerprint: item.HostKeyFingerprint,
	}
	switch meta.Kind {
	case credential.KindPassword:
		target.Password = func() (string, error) {
			_, secret, err := s.creds.Reveal(r.Context(), meta.ID)
			return secret, err
		}
	case credential.KindPrivateKey:
		target.PrivateKey = func() (string, error) {
			_, secret, err := s.creds.Reveal(r.Context(), meta.ID)
			return secret, err
		}
	default:
		http.Error(w, "凭据不能用于 SSH", http.StatusConflict)
		return
	}
	term, err := sshproxy.Connect(r.Context(), target)
	if err != nil {
		if errors.Is(err, sshproxy.ErrHostKeyMismatch) {
			http.Error(w, "主机密钥不符", http.StatusForbidden)
			return
		}
		log.Printf("ssh connect failed for asset %s", id)
		http.Error(w, "连接失败", http.StatusBadGateway)
		return
	}
	sessionID, err := s.sessions.Start(r.Context(), u.ID, item.ID)
	if err != nil {
		term.Close()
		log.Printf("ssh session log failed for asset %s", id)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		term.Close()
		s.endSession(sessionID)
		return
	}
	bridge(conn, term)
	term.Close()
	conn.Close(websocket.StatusNormalClosure, "")
	s.endSession(sessionID)
}

// endSession writes the end time. The timeout bounds this database write.
// It is not a session idle timeout and not a maximum duration.
func (s *Server) endSession(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.sessions.End(ctx, id); err != nil {
		log.Printf("session end failed")
	}
}

func bridge(conn *websocket.Conn, term *sshproxy.Terminal) {
	conn.SetReadLimit(256 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := term.Read(buf)
			if n > 0 {
				if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			kind, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			switch kind {
			case websocket.MessageText:
				cols, rows, ok := parseResize(data)
				if ok {
					_ = term.Resize(cols, rows)
				}
			case websocket.MessageBinary:
				if len(data) == 0 {
					continue
				}
				if _, err := term.Write(data); err != nil {
					return
				}
			}
		}
	}()
	<-done
	cancel()
}

func parseResize(data []byte) (int, int, bool) {
	if len(data) == 0 || len(data) > 64 {
		return 0, 0, false
	}
	var msg struct {
		Cols int `json:"cols"`
		Rows int `json:"rows"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&msg); err != nil {
		return 0, 0, false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return 0, 0, false
	}
	if msg.Cols < 1 || msg.Rows < 1 || msg.Cols > 500 || msg.Rows > 500 {
		return 0, 0, false
	}
	return msg.Cols, msg.Rows, true
}
