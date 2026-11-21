package web

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type accountPage struct {
	Email       string
	Since       string
	Networks    int
	Devices     int
	PwError     string
	DeleteError string
}

func (s *Server) accountData(r *http.Request) (*accountPage, error) {
	u := currentUser(r)
	nets, err := s.store.NetworksByUser(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	p := &accountPage{Email: u.Email, Since: u.CreatedAt.UTC().Format("2 January 2006"), Networks: len(nets)}
	for _, n := range nets {
		devs, err := s.store.DevicesByNetwork(r.Context(), n.ID)
		if err != nil {
			return nil, err
		}
		p.Devices += len(devs)
	}
	return p, nil
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, code int, mutate func(*accountPage)) {
	p, err := s.accountData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if mutate != nil {
		mutate(p)
	}
	if code != http.StatusOK {
		w.WriteHeader(code)
	}
	s.render(w, r, "account", p)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.renderAccount(w, r, http.StatusOK, nil)
}

// checkPassword verifies the signed-in user's password, counting failures
// towards the login lockout so this form can't be used for guessing.
func (s *Server) checkPassword(r *http.Request, pw string) (ok bool, locked string) {
	u := currentUser(r)
	account := strings.ToLower(u.Email)
	if blocked, wait := s.limits.loginAccount.blocked(account); blocked {
		return false, "Too many wrong passwords. Try again in " + waitText(wait) + "."
	}
	if len(pw) > maxPasswordBytes || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) != nil {
		s.limits.loginAccount.add(account)
		return false, ""
	}
	return true, ""
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	fail := func(code int, msg string) {
		s.renderAccount(w, r, code, func(p *accountPage) { p.PwError = msg })
	}
	ok, locked := s.checkPassword(r, r.FormValue("current"))
	switch {
	case locked != "":
		fail(http.StatusTooManyRequests, locked)
		return
	case !ok:
		fail(http.StatusUnauthorized, "Your current password is not correct.")
		return
	}
	next := r.FormValue("new")
	if msg := passwordProblem(next); msg != "" {
		fail(http.StatusBadRequest, msg)
		return
	}
	if next == r.FormValue("current") {
		fail(http.StatusBadRequest, "The new password is the same as the current one.")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	u := currentUser(r)
	if err := s.store.SetPassword(r.Context(), u.ID, string(hash)); err != nil {
		s.serverError(w, r, err)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteOtherSessions(r.Context(), u.ID, c.Value); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	redirectDone(w, r, "/account", "password-changed")
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	fail := func(code int, msg string) {
		s.renderAccount(w, r, code, func(p *accountPage) { p.DeleteError = msg })
	}
	if !strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), u.Email) {
		fail(http.StatusBadRequest, "Type your email address to confirm.")
		return
	}
	ok, locked := s.checkPassword(r, r.FormValue("password"))
	switch {
	case locked != "":
		fail(http.StatusTooManyRequests, locked)
		return
	case !ok:
		fail(http.StatusUnauthorized, "Your password is not correct.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.DeleteUser(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Revoke every key and DNS name of the account on the hub right away.
	if err := s.Sync(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure})
	redirectDone(w, r, "/", "account-deleted")
}
