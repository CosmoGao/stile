package web

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/coder/websocket"

	"github.com/CosmoGao/stile/internal/asset"
	"github.com/CosmoGao/stile/internal/credential"
	"github.com/CosmoGao/stile/internal/identity"
	"github.com/CosmoGao/stile/internal/rdpproxy"
)

func (s *Server) guacdAddress() string {
	v, _ := s.guacd.Load().(string)
	return v
}

// SetGuacdAddress replaces the guacd address. An empty address means RDP
// cannot dial. SSH does not read it.
func (s *Server) SetGuacdAddress(address string) {
	s.guacd.Store(address)
}

// openRDPPage shows the display only after the same checks as the socket,
// except it does not decrypt and does not dial guacd.
func (s *Server) openRDPPage(w http.ResponseWriter, r *http.Request, u identity.User, id string) {
	_, _, status, msg, ok := s.prepareRDP(r, u, id)
	if !ok {
		var view *viewAsset
		if status != http.StatusForbidden && status != http.StatusNotFound {
			if pub, err := s.assets.GetUser(r.Context(), id); err == nil {
				v := userAssetView(pub)
				view = &v
			}
		}
		s.renderOpen(w, r, u, status, msg, view, false, false)
		return
	}
	pub, err := s.assets.GetUser(r.Context(), id)
	if err != nil {
		log.Printf("rdp asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	view := userAssetView(pub)
	s.renderOpen(w, r, u, http.StatusOK, "", &view, false, true)
}

// rdpSocket is the same-origin Guacamole tunnel. The browser does not connect
// to guacd. The login cookie is sent by the browser. The page script does not
// receive the token or the password.
func (s *Server) rdpSocket(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	item, meta, status, msg, ok := s.prepareRDP(r, u, r.PathValue("id"))
	if !ok {
		http.Error(w, msg, status)
		return
	}
	address := s.guacdAddress()
	if address == "" {
		http.Error(w, "连接失败", http.StatusBadGateway)
		return
	}
	_, secret, err := s.creds.Reveal(r.Context(), meta.ID)
	if err != nil {
		log.Printf("rdp credential failed for asset %s", item.ID)
		http.Error(w, "连接失败", http.StatusBadGateway)
		return
	}
	width, height, dpi, tz := screenFromRequest(r)
	sess, err := rdpproxy.Handshake(r.Context(), address, rdpproxy.Target{
		Host:     item.Host,
		Port:     item.Port,
		Username: meta.LoginName,
		Password: secret,
		Width:    width,
		Height:   height,
		DPI:      dpi,
		Timezone: tz,
	}, nil)
	if err != nil {
		log.Printf("rdp handshake failed for asset %s", item.ID)
		http.Error(w, "连接失败", http.StatusBadGateway)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{"guacamole"},
	})
	if err != nil {
		sess.Close()
		return
	}
	sessionID, err := s.sessions.Start(r.Context(), u.ID, item.ID)
	if err != nil {
		sess.Close()
		conn.Close(websocket.StatusInternalError, "")
		log.Printf("rdp session log failed for asset %s", item.ID)
		return
	}
	proxyRDP(conn, sess)
	sess.Close()
	conn.Close(websocket.StatusNormalClosure, "")
	s.endSession(sessionID)
}

// prepareRDP checks the cookie, the grant, the protocol, and that the bound
// credential is a password. It does not decrypt and it does not dial guacd.
func (s *Server) prepareRDP(r *http.Request, u identity.User, id string) (asset.Asset, credential.Credential, int, string, bool) {
	if !validID(id) {
		return asset.Asset{}, credential.Credential{}, http.StatusNotFound, "资产不存在", false
	}
	if _, err := s.assets.GetUser(r.Context(), id); err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			return asset.Asset{}, credential.Credential{}, http.StatusNotFound, "资产不存在", false
		}
		log.Printf("rdp asset: %v", err)
		return asset.Asset{}, credential.Credential{}, http.StatusInternalServerError, "内部错误", false
	}
	allowed, err := s.grants.Allowed(r.Context(), u.ID, id)
	if err != nil {
		log.Printf("rdp grant: %v", err)
		return asset.Asset{}, credential.Credential{}, http.StatusInternalServerError, "内部错误", false
	}
	if !allowed {
		return asset.Asset{}, credential.Credential{}, http.StatusForbidden, openDenied, false
	}
	item, err := s.assets.Get(r.Context(), id)
	if err != nil {
		log.Printf("rdp asset: %v", err)
		return asset.Asset{}, credential.Credential{}, http.StatusInternalServerError, "内部错误", false
	}
	if item.Protocol != asset.ProtocolRDP {
		return asset.Asset{}, credential.Credential{}, http.StatusForbidden, "协议不是 RDP，不连接", false
	}
	if item.CredentialID == "" {
		return asset.Asset{}, credential.Credential{}, http.StatusConflict, "未绑定凭据，打不开", false
	}
	meta, err := s.creds.Lookup(r.Context(), item.CredentialID)
	if err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			return asset.Asset{}, credential.Credential{}, http.StatusConflict, "未绑定凭据，打不开", false
		}
		log.Printf("rdp credential: %v", err)
		return asset.Asset{}, credential.Credential{}, http.StatusInternalServerError, "内部错误", false
	}
	if meta.Kind != credential.KindPassword {
		return asset.Asset{}, credential.Credential{}, http.StatusConflict, "凭据必须是密码，不连接", false
	}
	return item, meta, 0, "", true
}

func screenFromRequest(r *http.Request) (width, height, dpi int, timezone string) {
	width = clampQuery(r.URL.Query().Get("GUAC_WIDTH"), 1024, 1, 8192)
	height = clampQuery(r.URL.Query().Get("GUAC_HEIGHT"), 768, 1, 8192)
	dpi = clampQuery(r.URL.Query().Get("GUAC_DPI"), 96, 1, 600)
	tz := r.URL.Query().Get("GUAC_TIMEZONE")
	if validTimezone(tz) {
		timezone = tz
	}
	return width, height, dpi, timezone
}

func clampQuery(raw string, fallback, min, max int) int {
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min {
		return fallback
	}
	if n > max {
		return max
	}
	return n
}

func validTimezone(tz string) bool {
	if tz == "" || len(tz) > 64 {
		return false
	}
	for _, r := range tz {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '/' || r == '_' || r == '+' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func proxyRDP(conn *websocket.Conn, sess *rdpproxy.Session) {
	conn.SetReadLimit(8 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var writeMu sync.Mutex
	write := func(p []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.Write(ctx, websocket.MessageText, p)
	}
	if err := write(rdpproxy.TunnelOpen()); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, _, raw, err := sess.Next()
			if len(raw) > 0 {
				if werr := write(raw); werr != nil {
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
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			if err := forwardBrowser(sess, data, write); err != nil {
				return
			}
		}
	}()
	<-done
	cancel()
}

func forwardBrowser(sess *rdpproxy.Session, data []byte, echo func([]byte) error) error {
	rd := rdpproxy.NewReader(strings.NewReader(string(data)))
	for {
		op, _, raw, err := rd.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// Empty opcode is the tunnel ping. Echo it and do not send it to guacd.
		if op == "" {
			if err := echo(raw); err != nil {
				return err
			}
			continue
		}
		if err := sess.Write(raw); err != nil {
			return err
		}
	}
}
