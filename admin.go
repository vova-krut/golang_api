package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Ban struct {
	WhoBanned    string
	WhenBanned   int64
	WhyBanned    string
	WhoUnbanned  string
	WhenUnbanned int64
}

type UserBan struct {
	Email     string
	BanReason string
}

func CheckActionPermission(w http.ResponseWriter, admin User, user User) bool {
	if (admin.Role == "admin" || admin.Role == "superadmin") && user.Role == "user" || admin.Role == "superadmin" && (user.Role == "user" || user.Role == "admin") {
		return true
	}
	w.WriteHeader(401)
	w.Write([]byte("you have no rights to perform this action"))
	return false
}

func IsBanned(user User) bool {
	if user.BanHistory == nil || user.BanHistory[len(user.BanHistory)-1].WhoBanned == "" || user.BanHistory[len(user.BanHistory)-1].WhoUnbanned != "" {
		return false
	}
	return true
}

func (u *UserService) AdminBan(w http.ResponseWriter, r *http.Request, admin User) {
	params := &UserBan{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(err, w)
		return
	}
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if !CheckActionPermission(w, admin, user) {
		return
	}
	if IsBanned(user) {
		handleError(errors.New("user "+user.Email+" is already banned"), w)
		return
	}
	ban := Ban{WhoBanned: admin.Email, WhenBanned: time.Now().Unix(), WhyBanned: params.BanReason, WhoUnbanned: "", WhenUnbanned: 0}
	user.BanHistory = append(user.BanHistory, ban)
	u.repository.Update(user.Email, user)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Banned user " + user.Email))
}

func (u *UserService) AdminUnban(w http.ResponseWriter, r *http.Request, admin User) {
	params := &UserBan{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(err, w)
		return
	}
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if !CheckActionPermission(w, admin, user) {
		return
	}
	if !IsBanned(user) {
		handleError(errors.New("user "+user.Email+" is not banned"), w)
		return
	}
	last_ban := user.BanHistory[len(user.BanHistory)-1]
	unban := Ban{WhoBanned: last_ban.WhoBanned, WhenBanned: last_ban.WhenBanned, WhyBanned: last_ban.WhyBanned, WhoUnbanned: admin.Email, WhenUnbanned: time.Now().Unix()}
	user.BanHistory[len(user.BanHistory)-1] = unban
	u.repository.Update(user.Email, user)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Unbanned user " + user.Email))
}

func (u *UserService) AdminInspect(w http.ResponseWriter, r *http.Request, admin User) {
	email := r.URL.Query().Get("email")
	user, err := u.repository.Get(email)
	if err != nil {
		handleError(err, w)
		return
	}
	if !CheckActionPermission(w, admin, user) {
		return
	}
	w.WriteHeader(http.StatusOK)
	if !IsBanned(user) {
		w.Write([]byte("user " + user.Email + " has no bans"))
		return
	}
	bans := fmt.Sprintf("user %v has those bans:\n", user.Email)
	for _, v := range user.BanHistory {
		bans += fmt.Sprintf("\tBanned by %v at %v for %v\n", v.WhoBanned, v.WhenBanned, v.WhyBanned)
		if v.WhoUnbanned != "" {
			bans += fmt.Sprintf("\t\t Unbanned by %v at %v", v.WhoUnbanned, v.WhenUnbanned)
		}
	}
	u.repository.Update(user.Email, user)
	w.Write([]byte(bans))
}

func (u *UserService) AdminPromote(w http.ResponseWriter, r *http.Request, admin User) {
	if admin.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("you have no rights to perform this action"))
		return
	}
	params := &UserBan{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(err, w)
		return
	}
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if IsBanned(user) {
		handleError(errors.New("user "+user.Email+" is banned"), w)
		return
	}
	user.Role = "admin"
	u.repository.Update(user.Email, user)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Promoted user " + user.Email))
}

func (u *UserService) AdminFire(w http.ResponseWriter, r *http.Request, admin User) {
	if admin.Role != "superadmin" {
		w.WriteHeader(401)
		w.Write([]byte("you have no rights to perform this action"))
		return
	}
	params := &UserBan{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(err, w)
		return
	}
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if IsBanned(user) {
		handleError(errors.New("admin "+user.Email+" is banned"), w)
		return
	}
	user.Role = "user"
	u.repository.Update(user.Email, user)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Fired admin " + user.Email))
}
