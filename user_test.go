package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type parsedResponse struct {
	status int
	body   []byte
}

func createRequester(t *testing.T) func(req *http.Request, err error) parsedResponse {
	return func(req *http.Request, err error) parsedResponse {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		resp, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}
		return parsedResponse{res.StatusCode, resp}
	}
}

func prepareParams(t *testing.T, params map[string]interface{}) io.Reader {
	body, err := json.Marshal(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	return bytes.NewBuffer(body)
}

func newTestUserService() *UserService {
	return &UserService{
		repository: NewInMemoryUserStorage(),
	}
}

func assertStatus(t *testing.T, expected int, r parsedResponse) {
	if r.status != expected {
		t.Errorf("Unexpected response status. Expected: %d, actual: %d", expected, r.status)
	}
}

func assertBody(t *testing.T, expected string, r parsedResponse) {
	actual := string(r.body)
	if actual != expected {
		t.Errorf("Unexpected response body. Expected: %s, actual: %s", expected, actual)
	}
}

func TestHandlers(t *testing.T) {

	doRequest := createRequester(t)
	u := newTestUserService()
	j, err := NewJWTService("pubkey.rsa", "privkey.rsa")
	if err != nil {
		t.FailNow()
	}
	JWT := ""
	t.Run("user does not exist", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("try acces to users/me without login", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ShowFavCake))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("registered", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 201, resp)
		assertBody(t, "registered", resp)
	})

	t.Run("user already exists", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "this login already exists", resp)
	})

	t.Run("no params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, nil))
		assertStatus(t, 422, resp)
		assertBody(t, "could not read params", resp)
	})

	t.Run("password is too short", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "pass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "password has to be at least 8 symbols", resp)
	})

	t.Run("invalid email", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "testmail.com",
			"password":      "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid email address", resp)
	})

	t.Run("empty favorite cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "fill in the favourite cake", resp)
	})

	t.Run("invalid favorite cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{}{
			"email":         "test@mail.com",
			"password":      "somepass",
			"favorite_cake": "213",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid favourite cake", resp)
	})

	t.Run("login", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		JWT = string(resp.body)
	})

	t.Run("login with wrong password", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "wrongpass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))

		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("unauth get cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.repository, getCakeHandler)))
		defer ts.Close()
		resp := doRequest(http.NewRequest(http.MethodGet, ts.URL, nil))
		assertStatus(t, 401, resp)
		assertBody(t, "unauthorized", resp)
	})

	t.Run("auth get cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.repository, getCakeHandler)))
		defer ts.Close()
		cakeReq, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
		cakeReq.Header.Set("Authorization", "Bearer "+JWT)
		resp := doRequest(cakeReq, nil)
		assertStatus(t, 200, resp)
		assertBody(t, "cheesecake", resp)
	})

	t.Run("try acces to users/me without params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ShowFavCake))
		defer ts.Close()
		resp := doRequest(http.NewRequest(http.MethodGet, ts.URL, nil))
		assertStatus(t, 422, resp)
		assertBody(t, "could not read params", resp)
	})

	t.Run("acces to users/me with params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ShowFavCake))
		defer ts.Close()
		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodGet, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "cheesecake", resp)
	})

	t.Run("changing fav_cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeCake))
		defer ts.Close()
		params := map[string]interface{}{
			"email":             "test@mail.com",
			"password":          "somepass",
			"new_favorite_cake": "Cupcake",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "favorite cake was changed", resp)
	})

	t.Run("changing fav_cake to invalid params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeCake))
		defer ts.Close()
		params := map[string]interface{}{
			"": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("changing fav_cake without params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeCake))
		defer ts.Close()
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, nil))
		assertStatus(t, 422, resp)
		assertBody(t, "could not read params", resp)
	})

	t.Run("changing email", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeEmail))
		defer ts.Close()
		params := map[string]interface{}{
			"email":     "test@mail.com",
			"password":  "somepass",
			"new_email": "testing@mail.com",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "email was changed", resp)
	})

	t.Run("changing email to invalid params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeEmail))
		defer ts.Close()
		params := map[string]interface{}{
			"": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("changing email to nil", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeEmail))
		defer ts.Close()
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, nil))
		assertStatus(t, 422, resp)
		assertBody(t, "could not read params", resp)
	})

	t.Run("changing password", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangePassword))
		defer ts.Close()
		params := map[string]interface{}{
			"email":        "testing@mail.com",
			"password":     "somepass",
			"new_password": "password",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "password was changed", resp)
	})

	t.Run("changing password to nil", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangePassword))
		defer ts.Close()
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, nil))
		assertStatus(t, 422, resp)
		assertBody(t, "could not read params", resp)
	})

	t.Run("changing password with invalid params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangePassword))
		defer ts.Close()
		params := map[string]interface{}{
			"": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})

	t.Run("ban user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "admin", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminBan)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":  user.Email,
			"reason": "test",
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, http.StatusOK, resp)
		assertBody(t, "Banned user "+user.Email, resp)
	})

	t.Run("ban user with no rights", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminBan)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":  user.Email,
			"reason": "test",
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 401, resp)
		assertBody(t, "you have no rights to perform this action", resp)
	})

	t.Run("try to ban user twice", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "admin", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminBan)))
		defer ts.Close()
		params := map[string]interface{}{
			"email":  user.Email,
			"reason": "test",
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		doRequest(req, err)
		resp := doRequest(req, err)
		assertStatus(t, 422, resp)
		assertBody(t, "user "+user.Email+" is already banned", resp)
	})

	t.Run("unban user that is not banned", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "admin", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminUnban)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": user.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 422, resp)
		assertBody(t, "user "+user.Email+" is not banned", resp)
	})

	t.Run("unban user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "admin", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		user.BanHistory = append(user.BanHistory, Ban{"admin@mail.com", time.Now().Unix(), "test", "", 0})
		userService.repository.Update(user.Email, user)
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminUnban)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": user.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, http.StatusOK, resp)
		assertBody(t, "Unbanned user "+user.Email, resp)
	})

	t.Run("unban user with no rights", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		user.BanHistory = append(user.BanHistory, Ban{"admin@mail.com", time.Now().Unix(), "test", "", 0})
		userService.repository.Update(user.Email, user)
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminUnban)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": user.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 401, resp)
		assertBody(t, "you have no rights to perform this action", resp)
	})

	t.Run("inspect no ban information", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "admin", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminInspect)))
		defer ts.Close()
		req, err := http.NewRequest(http.MethodGet, ts.URL+"?email="+user.Email, nil)
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, http.StatusOK, resp)
		assertBody(t, "user "+user.Email+" has no bans", resp)
	})

	t.Run("inspect ban information", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "admin", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		user.BanHistory = append(user.BanHistory, Ban{"admin@mail.com", time.Now().Unix(), "test", "", 0})
		userService.repository.Update(user.Email, user)
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminInspect)))
		defer ts.Close()
		req, err := http.NewRequest(http.MethodGet, ts.URL+"?email="+user.Email, nil)
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, http.StatusOK, resp)
		assertBody(t, fmt.Sprintf("user "+user.Email+" has those bans:\n\tBanned by %v at %d for %v\n", user.BanHistory[0].WhoBanned, user.BanHistory[0].WhenBanned, user.BanHistory[0].WhyBanned), resp)
	})

	t.Run("inspect ban information with no rights", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		adminJWT, _ := jwtService.GenearateJWT(users.storage[os.Getenv("CAKE_ADMIN_EMAIL")])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminInspect)))
		defer ts.Close()
		req, err := http.NewRequest(http.MethodGet, ts.URL+"?email="+user.Email, nil)
		req.Header.Add("Authorization", "Bearer "+adminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 401, resp)
		assertBody(t, "you have no rights to perform this action", resp)
	})

	t.Run("promote user to admin", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		superadminJWT, _ := jwtService.GenearateJWT(users.storage[superadmin.Email])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminPromote)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": user.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+superadminJWT)
		resp := doRequest(req, err)
		assertStatus(t, http.StatusOK, resp)
		assertBody(t, "Promoted user "+user.Email, resp)
	})

	t.Run("try to promote banned user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		superadminJWT, _ := jwtService.GenearateJWT(users.storage[superadmin.Email])
		user.BanHistory = append(user.BanHistory, Ban{"admin@mail.com", time.Now().Unix(), "test", "", 0})
		userService.repository.Update(user.Email, user)
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminPromote)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": user.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+superadminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 422, resp)
		assertBody(t, "user "+user.Email+" is banned", resp)
	})

	t.Run("promote user with no rights", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "admin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		superadminJWT, _ := jwtService.GenearateJWT(users.storage[superadmin.Email])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminPromote)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": user.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+superadminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 401, resp)
		assertBody(t, "you have no rights to perform this action", resp)
	})

	t.Run("fire admin to user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		superadminJWT, _ := jwtService.GenearateJWT(users.storage[superadmin.Email])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminFire)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": admin.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+superadminJWT)
		resp := doRequest(req, err)
		assertStatus(t, http.StatusOK, resp)
		assertBody(t, "Fired admin "+admin.Email, resp)
	})

	t.Run("fire admin to user", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "superadmin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		superadminJWT, _ := jwtService.GenearateJWT(users.storage[superadmin.Email])
		admin.BanHistory = append(admin.BanHistory, Ban{"superadmin@mail.com", time.Now().Unix(), "test", "", 0})
		userService.repository.Update(admin.Email, admin)
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminFire)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": admin.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+superadminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 422, resp)
		assertBody(t, "admin "+admin.Email+" is banned", resp)
	})

	t.Run("fire admin to user with no rights", func(t *testing.T) {
		users := NewInMemoryUserStorage()
		os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
		os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
		userService := UserService{repository: users}
		admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "user", "cheesecake", nil}
		superadmin := User{"superadmin@mail.com", "superpass", "admin", "cheesecake", nil}
		user := User{"test@mail.com", "somepass", "user", "pancakes", nil}
		userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
		userService.repository.Add("superadmin@mail.com", superadmin)
		userService.repository.Add("test@mail.com", user)
		jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
		if er != nil {
			panic(er)
		}
		superadminJWT, _ := jwtService.GenearateJWT(users.storage[superadmin.Email])
		ts := httptest.NewServer(http.HandlerFunc(jwtService.jwtAuth(users, userService.AdminFire)))
		defer ts.Close()
		params := map[string]interface{}{
			"email": admin.Email,
		}
		req, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		req.Header.Add("Authorization", "Bearer "+superadminJWT)
		resp := doRequest(req, err)
		assertStatus(t, 401, resp)
		assertBody(t, "you have no rights to perform this action", resp)
	})
}
