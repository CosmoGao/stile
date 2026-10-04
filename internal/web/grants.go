package web

import (
	"errors"
	"log"
	"net/http"

	"github.com/CosmoGao/stile/internal/asset"
	"github.com/CosmoGao/stile/internal/grant"
	"github.com/CosmoGao/stile/internal/identity"
)

const openDenied = "没有授权，打不开"

type viewGroup struct {
	ID      string
	Name    string
	Created string
	Members int
}

type viewMember struct {
	UserID   string
	Username string
	Admin    bool
}

type viewGrant struct {
	ID          string
	AssetID     string
	AssetName   string
	SubjectType string
	SubjectID   string
	SubjectName string
}

func (s *Server) assetsVisible(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var (
		views          []viewAsset
		showCredential bool
		title          = "已授权的资产"
	)
	if u.Role == identity.RoleAdmin {
		// Management visibility is every asset. Opening does not use this list.
		list, err := s.assets.List(r.Context())
		if err != nil {
			log.Printf("list assets: %v", err)
			http.Error(w, "内部错误", http.StatusInternalServerError)
			return
		}
		views = make([]viewAsset, 0, len(list))
		for _, item := range list {
			views = append(views, s.assetView(item))
		}
		showCredential = true
		title = "全部资产"
	} else {
		// Query the grant union only. Do not load credential_id.
		list, err := s.grants.ListForUser(r.Context(), u.ID)
		if err != nil {
			log.Printf("list granted assets: %v", err)
			http.Error(w, "内部错误", http.StatusInternalServerError)
			return
		}
		views = make([]viewAsset, 0, len(list))
		for _, item := range list {
			views = append(views, userAssetView(item))
		}
	}
	vu := s.view(u, u.ID)
	s.render(w, http.StatusOK, "visible_assets", page{
		Title:          title,
		Notice:         noticeText(r),
		CSRF:           s.ensureCSRF(w, r),
		User:           &vu,
		Assets:         views,
		ShowCredential: showCredential,
	})
}

func userAssetView(a asset.UserAsset) viewAsset {
	return viewAsset{
		ID:       a.ID,
		Name:     a.Name,
		Protocol: a.Protocol,
		Host:     a.Host,
		Port:     a.Port,
	}
}

// assetOpen checks authorization before showing an SSH terminal.
// A failed check does not decrypt a credential and does not dial.
// RDP is still not connected and does not use guacd.
func (s *Server) assetOpen(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	pub, err := s.assets.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			s.renderOpen(w, r, u, http.StatusNotFound, "资产不存在", nil, false)
			return
		}
		log.Printf("open asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	allowed, err := s.grants.Allowed(r.Context(), u.ID, id)
	if err != nil {
		log.Printf("open grant: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	if !allowed {
		// Do not echo the asset. No credential is decrypted and nothing is dialed.
		s.renderOpen(w, r, u, http.StatusForbidden, openDenied, nil, false)
		return
	}
	full, err := s.assets.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, asset.ErrNotFound) {
			s.renderOpen(w, r, u, http.StatusNotFound, "资产不存在", nil, false)
			return
		}
		log.Printf("open asset: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	view := userAssetView(pub)
	if full.Protocol != asset.ProtocolSSH {
		s.renderOpen(w, r, u, http.StatusOK, "这一段不打开 RDP，也不连接 guacd。", &view, false)
		return
	}
	if full.CredentialID == "" {
		s.renderOpen(w, r, u, http.StatusConflict, "未绑定凭据，打不开", &view, false)
		return
	}
	if full.HostKeyFingerprint == "" {
		s.renderOpen(w, r, u, http.StatusConflict, "还没有登记主机密钥指纹，不连接", &view, false)
		return
	}
	s.renderOpen(w, r, u, http.StatusOK, "", &view, true)
}

func (s *Server) renderOpen(w http.ResponseWriter, r *http.Request, u identity.User, status int, msg string, item *viewAsset, terminal bool) {
	vu := s.view(u, u.ID)
	title := "打开"
	if terminal && item != nil {
		title = item.Name
	}
	s.render(w, status, "open", page{
		Title:    title,
		Error:    msg,
		CSRF:     s.ensureCSRF(w, r),
		User:     &vu,
		Open:     item,
		Terminal: terminal,
	})
}

func (s *Server) groupsGet(w http.ResponseWriter, r *http.Request) {
	s.renderGroups(w, r, http.StatusOK, "")
}

func (s *Server) groupsCreate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	_, err := identity.CreateGroup(r.Context(), s.db, r.PostFormValue("name"), s.now())
	if err != nil {
		msg := "保存失败"
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, identity.ErrBadName):
			msg = "名称无效"
		case errors.Is(err, identity.ErrDuplicate):
			msg = "名称已存在"
		default:
			log.Printf("create group: %v", err)
			status = http.StatusInternalServerError
			msg = "保存失败"
		}
		s.renderGroups(w, r, status, msg)
		return
	}
	http.Redirect(w, r, "/admin/groups?notice=group-created", http.StatusSeeOther)
}

func (s *Server) groupsDelete(w http.ResponseWriter, r *http.Request) {
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
	if err := identity.DeleteGroup(r.Context(), s.db, id); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("delete group: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/groups?notice=group-deleted", http.StatusSeeOther)
}

func (s *Server) groupGet(w http.ResponseWriter, r *http.Request) {
	s.renderGroup(w, r, http.StatusOK, "")
}

func (s *Server) groupAddMember(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	id := r.PathValue("id")
	userID := r.PostFormValue("user_id")
	if !validID(id) || !validID(userID) {
		http.NotFound(w, r)
		return
	}
	if err := identity.AddMember(r.Context(), s.db, id, userID); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			s.renderGroup(w, r, http.StatusNotFound, "用户或用户组不存在")
			return
		}
		if errors.Is(err, identity.ErrDuplicate) {
			s.renderGroup(w, r, http.StatusConflict, "已经是成员")
			return
		}
		log.Printf("add member: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/groups/"+id+"?notice=member-added", http.StatusSeeOther)
}

func (s *Server) groupRemoveMember(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	id := r.PathValue("id")
	userID := r.PathValue("userID")
	if !validID(id) || !validID(userID) {
		http.NotFound(w, r)
		return
	}
	if err := identity.RemoveMember(r.Context(), s.db, id, userID); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("remove member: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/groups/"+id+"?notice=member-removed", http.StatusSeeOther)
}

func (s *Server) grantsGet(w http.ResponseWriter, r *http.Request) {
	s.renderGrants(w, r, http.StatusOK, "")
}

func (s *Server) grantsCreate(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.postOK(w, r) {
		return
	}
	subjectType := r.PostFormValue("subject_type")
	var subjectID string
	switch subjectType {
	case grant.SubjectUser:
		subjectID = r.PostFormValue("user_id")
	case grant.SubjectGroup:
		subjectID = r.PostFormValue("group_id")
	default:
		s.renderGrants(w, r, http.StatusBadRequest, "请选择用户或用户组")
		return
	}
	if !validID(r.PostFormValue("asset_id")) || !validID(subjectID) {
		s.renderGrants(w, r, http.StatusBadRequest, "请选择资产和主体")
		return
	}
	_, err := s.grants.Add(r.Context(), r.PostFormValue("asset_id"), subjectType, subjectID, u.ID)
	if err != nil {
		switch {
		case errors.Is(err, grant.ErrBadInput):
			s.renderGrants(w, r, http.StatusBadRequest, "请选择资产和主体")
		case errors.Is(err, grant.ErrNotFound):
			s.renderGrants(w, r, http.StatusNotFound, "资产、用户或用户组不存在")
		case errors.Is(err, grant.ErrDuplicate):
			s.renderGrants(w, r, http.StatusConflict, "同一资产和主体已经有授权")
		default:
			log.Printf("create grant: %v", err)
			http.Error(w, "内部错误", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/admin/grants?notice=grant-created", http.StatusSeeOther)
}

func (s *Server) grantsRevoke(w http.ResponseWriter, r *http.Request) {
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
	if err := s.grants.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, grant.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("revoke grant: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/grants?notice=grant-revoked", http.StatusSeeOther)
}

func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	list, err := identity.ListGroups(r.Context(), s.db)
	if err != nil {
		log.Printf("list groups: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	views := make([]viewGroup, 0, len(list))
	for _, item := range list {
		views = append(views, viewGroup{
			ID:      item.ID,
			Name:    item.Name,
			Created: formatStamp(item.CreatedAt),
			Members: item.Members,
		})
	}
	vu := s.view(u, u.ID)
	s.render(w, status, "groups", page{
		Title:  "用户组",
		Error:  msg,
		Notice: noticeText(r),
		CSRF:   s.ensureCSRF(w, r),
		User:   &vu,
		Groups: views,
	})
}

func (s *Server) renderGroup(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	g, err := identity.GetGroup(r.Context(), s.db, id)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Printf("get group: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	members, err := identity.ListMembers(r.Context(), s.db, id)
	if err != nil {
		log.Printf("list members: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	users, err := identity.List(r.Context(), s.db)
	if err != nil {
		log.Printf("list users: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	mv := make([]viewMember, 0, len(members))
	for _, item := range members {
		mv = append(mv, viewMember{UserID: item.UserID, Username: item.Username, Admin: item.Role == identity.RoleAdmin})
	}
	uv := make([]viewUser, 0, len(users))
	for _, item := range users {
		uv = append(uv, s.view(item, u.ID))
	}
	vg := viewGroup{ID: g.ID, Name: g.Name, Created: formatStamp(g.CreatedAt), Members: g.Members}
	vu := s.view(u, u.ID)
	s.render(w, status, "group", page{
		Title:   g.Name,
		Error:   msg,
		Notice:  noticeText(r),
		CSRF:    s.ensureCSRF(w, r),
		User:    &vu,
		Group:   &vg,
		Members: mv,
		Users:   uv,
	})
}

func (s *Server) renderGrants(w http.ResponseWriter, r *http.Request, status int, msg string) {
	u, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	list, err := s.grants.List(r.Context())
	if err != nil {
		log.Printf("list grants: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	assets, err := s.assets.List(r.Context())
	if err != nil {
		log.Printf("list assets: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	users, err := identity.List(r.Context(), s.db)
	if err != nil {
		log.Printf("list users: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	groups, err := identity.ListGroups(r.Context(), s.db)
	if err != nil {
		log.Printf("list groups: %v", err)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	gv := make([]viewGrant, 0, len(list))
	for _, item := range list {
		gv = append(gv, viewGrant{
			ID:          item.ID,
			AssetID:     item.AssetID,
			AssetName:   item.AssetName,
			SubjectType: item.SubjectType,
			SubjectID:   item.SubjectID,
			SubjectName: item.SubjectName,
		})
	}
	av := make([]viewAsset, 0, len(assets))
	for _, item := range assets {
		av = append(av, s.assetView(item))
	}
	uv := make([]viewUser, 0, len(users))
	for _, item := range users {
		uv = append(uv, s.view(item, u.ID))
	}
	gg := make([]viewGroup, 0, len(groups))
	for _, item := range groups {
		gg = append(gg, viewGroup{ID: item.ID, Name: item.Name, Members: item.Members})
	}
	vu := s.view(u, u.ID)
	s.render(w, status, "grants", page{
		Title:  "授权",
		Error:  msg,
		Notice: noticeText(r),
		CSRF:   s.ensureCSRF(w, r),
		User:   &vu,
		Grants: gv,
		Assets: av,
		Users:  uv,
		Groups: gg,
	})
}
