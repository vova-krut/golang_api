package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type parsedResponse struct {
 status int
 body []byte

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
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})
	
	t.Run("registered", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 201, resp)
		assertBody(t, "registered", resp)
	})

	t.Run("user already exists", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
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
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "pass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "password has to be at least 8 symbols", resp)
	})

	t.Run("invalid email", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "testmail.com",
			"password": "somepass",
			"favorite_cake": "cheesecake",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid email address", resp)
	})

	t.Run("empty favorite cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
			"favorite_cake": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "fill in the favourite cake", resp)
	})

	t.Run("invalid favorite cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
			"favorite_cake": "213",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid favourite cake", resp)
	})

	t.Run("login", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		JWT = string(resp.body)
	})

	t.Run("login with wrong password", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "test@mail.com",
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
		cakeReq.Header.Set("Authorization", "Bearer " + JWT)
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
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
		}
		resp := doRequest(http.NewRequest(http.MethodGet, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "cheesecake", resp)
	})

	t.Run("changing fav_cake", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeCake))
		defer ts.Close()
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
			"new_favorite_cake": "Cupcake",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "favorite cake was changed", resp)
	})

	t.Run("changing fav_cake to invalid params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeCake))
		defer ts.Close()
		params := map[string]interface{} {
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
		params := map[string]interface{} {
			"email": "test@mail.com",
			"password": "somepass",
			"new_email": "testing@mail.com",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBody(t, "email was changed", resp)
	})

	t.Run("changing email to invalid params", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(u.ChangeEmail))
		defer ts.Close()
		params := map[string]interface{} {
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
		params := map[string]interface{} {
			"email": "testing@mail.com",
			"password": "somepass",
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
		params := map[string]interface{} {
			"": "",
		}
		resp := doRequest(http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)
	})
}