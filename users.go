package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

type User struct {
	Email          string
	PasswordDigest string
	Role           string
	FavoriteCake   string
	BanHistory     []Ban
}

type UserRepository interface {
	Add(string, User) error
	Get(string) (User, error)
	Update(string, User) error
	Delete(string) (User, error)
}

type UserService struct {
	repository UserRepository
}

type UserRegisterParams struct {
	// If it looks strange, read about golang struct tags
	Email        string `json:"email"`
	Password     string `json:"password"`
	FavoriteCake string `json:"favorite_cake"`
}

type UserChangeParams struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	FavoriteCake     string `json:"favorite_cake"`
	New_Email        string `json:"new_email"`
	New_Password     string `json:"new_password"`
	New_FavoriteCake string `json:"new_favorite_cake"`
}

func validateRegisterParams(p *UserRegisterParams) error {
	// 1. Email is valid
	match_email, _ := regexp.Match(`(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)`, []byte(p.Email))
	if !match_email {
		return errors.New("invalid email address")
	}
	// 2. Password at least 8 symbols
	if len(p.Password) < 8 {
		return errors.New("password has to be at least 8 symbols")
	}
	// 3. Favorite cake not empty
	if len(p.FavoriteCake) == 0 {
		return errors.New("fill in the favourite cake")
	}
	// 4. Favorite cake only alphabetic
	match_cake, _ := regexp.Match(`^[a-zA-Z]+$`, []byte(p.FavoriteCake))
	if !match_cake {
		return errors.New("invalid favourite cake")
	}
	return nil
}

func (u *UserService) Register(w http.ResponseWriter, r *http.Request) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	newUser := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
		Role:           "user",
	}
	err = u.repository.Add(params.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered"))
}

func handleError(err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	w.Write([]byte(err.Error()))
}

func (u *UserService) ShowFavCake(w http.ResponseWriter, r *http.Request) {
	params := &JWTParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if IsBanned(user) {
		w.WriteHeader(401)
		w.Write([]byte("u are banned because " + user.BanHistory[len(user.BanHistory)-1].WhyBanned))
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid password"), w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(user.FavoriteCake))
}

func (u *UserService) ChangeCake(w http.ResponseWriter, r *http.Request) {
	params := &UserChangeParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if IsBanned(user) {
		w.WriteHeader(401)
		w.Write([]byte("u are banned because " + user.BanHistory[len(user.BanHistory)-1].WhyBanned))
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid password"), w)
		return
	}
	new_user := User{user.Email, user.PasswordDigest, user.Role, params.New_FavoriteCake, user.BanHistory}
	u.repository.Update(user.Email, new_user)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("favorite cake was changed"))
}

func (u *UserService) ChangeEmail(w http.ResponseWriter, r *http.Request) {
	params := &UserChangeParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if IsBanned(user) {
		w.WriteHeader(401)
		w.Write([]byte("u are banned because " + user.BanHistory[len(user.BanHistory)-1].WhyBanned))
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid password"), w)
		return
	}
	new_user := User{params.New_Email, user.PasswordDigest, user.Role, user.FavoriteCake, user.BanHistory}
	u.repository.Delete(user.Email)
	u.repository.Add(new_user.Email, new_user)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("email was changed"))
}

func (u *UserService) ChangePassword(w http.ResponseWriter, r *http.Request) {
	params := &UserChangeParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}
	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	if IsBanned(user) {
		w.WriteHeader(401)
		w.Write([]byte("u are banned because " + user.BanHistory[len(user.BanHistory)-1].WhyBanned))
	}
	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid password"), w)
		return
	}
	newPasswordDigest := md5.New().Sum([]byte(params.New_Password))
	new_user := User{user.Email, string(newPasswordDigest), user.Role, user.FavoriteCake, user.BanHistory}
	u.repository.Update(user.Email, new_user)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("password was changed"))
}
