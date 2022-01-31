package main

import (
	"encoding/json"
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
	Email string
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
	ban := Ban{WhoBanned: admin.Email, WhenBanned: time.Now().Unix(), WhyBanned: params.BanReason, WhoUnbanned: "", WhenUnbanned: 0}
	user.BanHistory = append(user.BanHistory, ban)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Banned user "))
}