package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

func getCakeHandler(w http.ResponseWriter, r *http.Request, u User) {
 	w.Write([]byte(u.FavoriteCake))
}

func wrapJwt( jwt *JWTService, f func(http.ResponseWriter, *http.Request, *JWTService) ) http.HandlerFunc {
 	return func(rw http.ResponseWriter, r *http.Request) {
 		f(rw, r, jwt)
 	}
}

func main() {
	r := mux.NewRouter()
	users := NewInMemoryUserStorage()
	os.Setenv("CAKE_ADMIN_EMAIL", "admin@mail.com")
	os.Setenv("CAKE_ADMIN_PASSWORD", "adminpass")
 	userService := UserService {repository: users}
	admin := User{os.Getenv("CAKE_ADMIN_EMAIL"), os.Getenv("CAKE_ADMIN_PASSWORD"), "admin", "cheesecake", make([]Ban, 0)}
	userService.repository.Add(os.Getenv("CAKE_ADMIN_EMAIL"), admin)
	jwtService, er := NewJWTService("pubkey.rsa", "privkey.rsa")
 	if er != nil {
 		panic(er)
 	} 
 	r.HandleFunc("/cake", logRequest(jwtService.jwtAuth(users, getCakeHandler))).Methods(http.MethodGet)
 	r.HandleFunc("/user/register", logRequest(userService.Register)).Methods(http.MethodPost)
	r.HandleFunc("/user/jwt", logRequest(wrapJwt(jwtService, userService.JWT))).Methods(http.MethodPost)
	r.HandleFunc("/user/me", logRequest(userService.ShowFavCake)).Methods(http.MethodGet)
	r.HandleFunc("/user/favorite_cake", logRequest(userService.ChangeCake)).Methods(http.MethodPut)
	r.HandleFunc("/user/email", logRequest(userService.ChangeEmail)).Methods(http.MethodPut)
	r.HandleFunc("/user/password", logRequest(userService.ChangePassword)).Methods(http.MethodPut)
	r.HandleFunc("/admin/ban", logRequest(jwtService.jwtAuth(users, userService.AdminBan))).Methods(http.MethodPost)
	r.HandleFunc("/admin/unban", logRequest(jwtService.jwtAuth(users, userService.AdminUnban))).Methods(http.MethodPost)
	r.HandleFunc("/admin/inspect", logRequest(jwtService.jwtAuth(users, userService.AdminInspect))).Methods(http.MethodGet)
	r.HandleFunc("/admin/promote", logRequest(jwtService.jwtAuth(users, userService.AdminPromote))).Methods(http.MethodPost)
	r.HandleFunc("/admin/fire", logRequest(jwtService.jwtAuth(users, userService.AdminFire))).Methods(http.MethodPost)
 	srv := http.Server {
 		Addr: ":8080",
 		Handler: r,
 	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	log.Println("Server started, hit Ctrl+C to stop")
	err := srv.ListenAndServe()
	if err != nil {
		log.Println("Server exited with error:", err)
	}
	log.Println("Good bye :)")
}