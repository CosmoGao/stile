package web

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/CosmoGao/stile/internal/asset"
	"github.com/CosmoGao/stile/internal/credential"
)

type viewAsset struct {
	ID             string
	Name           string
	Protocol       string
	Host           string
	Port           int
	CredentialID   string
	CredentialName string
	HostKey        string
	Created        string
	Updated        string
}

type viewCredential struct {
	ID          string
	Name        string
	Kind        string
	LoginName   string
	Fingerprint string
	Created     string
	Updated     string
}

func (s *Server) assetsGet(w http.ResponseWriter, r *http.Request) {
	s.renderAssets(w, r, http.StatusOK, "")
}

func (s *Server) assetsCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	_, err := s.assets.Create(r.Context(), assetInput(r))
	if err != nil {
		s.failAsset(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/assets?notice=asset-saved", http.StatusSeeOther)
}

func (s *Server) assetsUpdate(w http.ResponseWriter, r *http.Request) {
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
	_, err := s.assets.Update(r.Context(), id, assetInput(r))
	if err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		s.failAsset(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/assets?notice=asset-saved", http.StatusSeeOther)
}

func (s *Server) assetsDelete(w http.ResponseWriter, r *http.Request) {
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
	if err := s.assets.Delete(r.Context(), id); err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("delete asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/assets?notice=asset-deleted", http.StatusSeeOther)
}

func (s *Server) failAsset(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, asset.ErrBadInput):
		s.renderAssets(w, r, http.StatusBadRequest, "请检查名称、地址、协议或端口")
	case errors.Is(err, asset.ErrCredentialMissing):
		s.renderAssets(w, r, http.StatusBadRequest, "凭据不存在")
	default:
		log.Printf("save asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
	}
}

func assetInput(r *http.Request) asset.Input {
	return asset.Input{
		Name:               r.PostFormValue("name"),
		Protocol:           r.PostFormValue("protocol"),
		Host:               r.PostFormValue("host"),
		Port:               r.PostFormValue("port"),
		CredentialID:       r.PostFormValue("credential_id"),
		HostKeyFingerprint: r.PostFormValue("ssh_host_key_fingerprint"),
	}
}

func (s *Server) credentialsGet(w http.ResponseWriter, r *http.Request) {
	s.renderCredentials(w, r, http.StatusOK, "")
}

func (s *Server) credentialsCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	_, err := s.creds.Create(r.Context(), credentialInput(r))
	if err != nil {
		s.failCredential(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/credentials?notice=credential-saved", http.StatusSeeOther)
}

func (s *Server) credentialsReplace(w http.ResponseWriter, r *http.Request) {
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
	_, err := s.creds.Replace(r.Context(), id, credentialInput(r))
	if err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		s.failCredential(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/credentials?notice=credential-replaced", http.StatusSeeOther)
}

func (s *Server) credentialsDelete(w http.ResponseWriter, r *http.Request) {
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
	if err := s.creds.Delete(r.Context(), id); err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if errors.Is(err, credential.ErrInUse) {
			s.renderCredentials(w, r, http.StatusConflict, "仍被资产引用，不能删除")
			return
		}
		log.Printf("delete credential: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/credentials?notice=credential-deleted", http.StatusSeeOther)
}

func (s *Server) credentialsView(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	// Read and decrypt only. Do not write a login log or any other row.
	item, secret, err := s.creds.Reveal(r.Context(), id)
	if err != nil {
		if errors.Is(err, credential.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("reveal credential: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	shown := s.credentialView(item)
	vu := s.view(u, u.ID)
	s.render(w, http.StatusOK, "credential_view", page{
		Title:  "查看凭据",
		CSRF:   s.ensureCSRF(w, r),
		User:   &vu,
		Shown:  &shown,
		Secret: secret,
	})
}

func (s *Server) failCredential(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, credential.ErrBadInput):
		s.renderCredentials(w, r, http.StatusBadRequest, "请检查名称、登录名或口令")
	case errors.Is(err, credential.ErrBadKey):
		s.renderCredentials(w, r, http.StatusBadRequest, "私钥无效")
	case errors.Is(err, credential.ErrPassphraseRequired):
		s.renderCredentials(w, r, http.StatusBadRequest, "请填写私钥口令")
	case errors.Is(err, credential.ErrBadPassphrase):
		s.renderCredentials(w, r, http.StatusBadRequest, "私钥口令不正确")
	default:
		log.Printf("save credential: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
	}
}

func credentialInput(r *http.Request) credential.Input {
	return credential.Input{
		Name:          r.PostFormValue("name"),
		Kind:          r.PostFormValue("kind"),
		LoginName:     r.PostFormValue("login_name"),
		Secret:        r.PostFormValue("secret"),
		KeyPassphrase: r.PostFormValue("key_passphrase"),
	}
}

func (s *Server) renderAssets(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	list, err := s.assets.List(r.Context())
	if err != nil {
		log.Printf("list assets: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	creds, err := s.creds.List(r.Context())
	if err != nil {
		log.Printf("list credentials: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	views := make([]viewAsset, 0, len(list))
	for _, item := range list {
		views = append(views, s.assetView(item))
	}
	cv := make([]viewCredential, 0, len(creds))
	for _, item := range creds {
		cv = append(cv, s.credentialView(item))
	}
	vu := s.view(u, u.ID)
	s.render(w, status, "assets", page{
		Title:       "资产",
		Error:       msg,
		Notice:      noticeText(r),
		CSRF:        s.ensureCSRF(w, r),
		User:        &vu,
		Assets:      views,
		Credentials: cv,
	})
}

func (s *Server) renderCredentials(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	list, err := s.creds.List(r.Context())
	if err != nil {
		log.Printf("list credentials: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	views := make([]viewCredential, 0, len(list))
	for _, item := range list {
		views = append(views, s.credentialView(item))
	}
	vu := s.view(u, u.ID)
	s.render(w, status, "credentials", page{
		Title:       "凭据",
		Error:       msg,
		Notice:      noticeText(r),
		CSRF:        s.ensureCSRF(w, r),
		User:        &vu,
		Credentials: views,
	})
}

func (s *Server) assetView(a asset.Asset) viewAsset {
	return viewAsset{
		ID:             a.ID,
		Name:           a.Name,
		Protocol:       a.Protocol,
		Host:           a.Host,
		Port:           a.Port,
		CredentialID:   a.CredentialID,
		CredentialName: a.CredentialName,
		HostKey:        a.HostKeyFingerprint,
		Created:        formatStamp(a.CreatedAt),
		Updated:        formatStamp(a.UpdatedAt),
	}
}

func (s *Server) credentialView(c credential.Credential) viewCredential {
	return viewCredential{
		ID:          c.ID,
		Name:        c.Name,
		Kind:        c.Kind,
		LoginName:   c.LoginName,
		Fingerprint: c.Fingerprint,
		Created:     formatStamp(c.CreatedAt),
		Updated:     formatStamp(c.UpdatedAt),
	}
}

func formatStamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}
