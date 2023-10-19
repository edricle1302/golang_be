package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	config "messenger/Config"
	mongodb_handler "messenger/MongoDB"
	util "messenger/Util"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

var conf = config.GetConfig("config.yaml")
var ctx = context.TODO()

// ------------------------------

// func HandleLogin(w http.ResponseWriter, r *http.Request) {

// 	db := mysql_handler.Init_database(os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_DB"))
// 	defer db.Close()

// 	bodyStruct, err := util.RequestToStruct(r)
// 	if err != nil {
// 		fmt.Println("Parse body error at login:", err)
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Parse body failed",
// 			"exit_code": conf.GetInt("exit_code.internal_error"),
// 		})
// 		return
// 	}
// 	email, email_check := bodyStruct["email"].(string)
// 	password, password_check := bodyStruct["password"].(string)
// 	if !(email_check && password_check) {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Not enough params",
// 			"exit_code": conf.GetInt("exit_code.invalid_field"),
// 		})
// 		return
// 	}
// 	account, err := mysql_handler.Get_account(db, email)
// 	if err != nil {
// 		fmt.Println("Get account error:", err)
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Get account failed",
// 			"exit_code": conf.GetInt("exit_code.internal_error"),
// 		})
// 		return
// 	}
// 	if account == nil {
// 		fmt.Println("Account is not existed")
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Email or password is wrong",
// 			"exit_code": conf.GetInt("exit_code.wrong_credentials"),
// 		})
// 		return
// 	}

// 	if account["is_locked"].(bool) {
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Account is locked",
// 			"exit_code": conf.GetInt("exit_code.locked_account"),
// 		})
// 		return
// 	}
// 	if account["password"] != util.Hash_sha256(password) {
// 		fmt.Println("Password is wrong")
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Email or password is wrong",
// 			"exit_code": conf.GetInt("exit_code.wrong_credentials"),
// 		})
// 		return
// 	}
// 	if account["verified"].(string) == "0" {
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "User email is not verified",
// 			"exit_code": conf.GetInt("exit_code.unverified_email"),
// 		})
// 		return
// 	}
// 	userinfo, err := mysql_handler.Get_user(db, email)
// 	if err != nil {
// 		fmt.Println("Get user error:", err)
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Get user failed",
// 			"exit_code": conf.GetInt("exit_code.internal_error"),
// 		})
// 		return
// 	}
// 	sessionToken, err := cache.GetFromRedis(ctx, email, redisClient)
// 	if err != nil || sessionToken == "" {
// 		sessionToken = util.GenerateSessionToken()
// 		err = cache.SetToRedis(ctx, email, sessionToken, 31536000, redisClient)
// 		if err != nil {
// 			fmt.Println("Set to redis failed:", err)
// 			w.WriteHeader(http.StatusInternalServerError)
// 			w.Header().Set("Content-Type", "application/json")
// 			json.NewEncoder(w).Encode(map[string]interface{}{
// 				"message":   "Set to redis failed",
// 				"exit_code": conf.GetInt("exit_code.internal_error"),
// 			})
// 			return
// 		}
// 	}
// 	w.WriteHeader(http.StatusOK)
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"user":      userinfo,
// 		"token":     sessionToken,
// 		"exit_code": conf.GetInt("exit_code.success"),
// 	})
// }

func HandleSignup(w http.ResponseWriter, r *http.Request) {
	db := mongodb_handler.Init_database(os.Getenv("MONGODB_HOST"), os.Getenv("MONGODB_PORT"), os.Getenv("MONGODB_DATABASE"))
	defer db.Client().Disconnect(context.TODO())
	bodyStruct, err := util.RequestToStruct(r)
	if err != nil {
		fmt.Println("Parse body error at signup:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Parse body failed",
			"exit_code": conf.GetInt("exit_code.internal_error"),
		})
		return
	}

	if bodyStruct["user_type"] == nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "User type can not be nil",
			"exit_code": conf.GetInt("exit_code.invalid_field"),
		})
		return
	}

	user_type := bodyStruct["user_type"]

	user_types := []string{}
	user_type_valid_fields := map[string][]string{
		"user":  {"user_type", "email", "password", "name", "dob", "phone", "avatar"},
		"admin": {"user_type", "email", "password", "name", "phone", "avatar"},
	}
	for key := range user_type_valid_fields {
		user_types = append(user_types, key)
	}
	if !util.Contains(user_types, user_type.(string)) {
		fmt.Println("[+] user_type:", user_type)

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "User type is not valid",
			"exit_code": conf.GetInt("exit_code.invalid_field"),
		})
		return
	}
	for key := range bodyStruct {
		if !util.Contains(user_type_valid_fields[user_type.(string)], key) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			fmt.Println(err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":   "Field " + key + " is not valid",
				"exit_code": conf.GetInt("exit_code.invalid_field"),
			})
			return
		}
	}

	for _, field := range user_type_valid_fields[user_type.(string)] {
		if _, ok := bodyStruct[field]; !ok {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message":   "Field " + field + " is required",
				"exit_code": conf.GetInt("exit_code.invalid_field"),
			})
			return
		}
	}

	email := bodyStruct["email"]

	account, err := mongodb_handler.Get_account(db, email.(string))

	if err != nil {
		fmt.Println("Get account error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		fmt.Println(err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Get account failed",
			"exit_code": conf.GetInt("exit_code.internal_error"),
		})
		return
	}

	if account != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		fmt.Println(err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Email is already existed",
			"exit_code": conf.GetInt("exit_code.email_exists"),
		})
		return
	}

	switch user_type.(string) {
	case "user":
		err = util.HandleImageRelatedFields(&bodyStruct, []string{"avatar"}, email.(string))
	case "admin":
		err = util.HandleImageRelatedFields(&bodyStruct, []string{"avatar"}, email.(string))
	}

	if err != nil {
		fmt.Println("Handle image related fields error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("Image related err: ", err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Handle image related fields failed",
			"exit_code": conf.GetInt("exit_code.internal_error"),
		})
		return
	}

	err = mongodb_handler.Create_account(db, bodyStruct)
	if err != nil {
		fmt.Println("Create user error:", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "Create user failed",
			"exit_code": conf.GetInt("exit_code.internal_error"),
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Signup successfully",
		"exit_code": conf.GetInt("exit_code.success"),
	})
}

// func HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
// 	bodyStruct, err := util.RequestToStruct(r)

// 	if err != nil {
// 		fmt.Println("Parse body error at refresh token:", err)
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Parse body failed",
// 			"exit_code": conf.GetInt("exit_code.internal_error"),
// 		})
// 		return
// 	}
// 	email, emailCheck := bodyStruct["email"]
// 	usrToken, usrTokenCheck := bodyStruct["token"]
// 	if !(emailCheck && usrTokenCheck) {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Header().Set("Content-Type", "application/json")
// 		fmt.Println(err)
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Not enough params",
// 			"exit_code": conf.GetInt("exit_code.invalid_field"),
// 		})
// 		return
// 	}
// 	token, err := cache.GetFromRedis(ctx, email.(string), redisClient)
// 	if err != nil {
// 		fmt.Println(err)
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "unauthorized",
// 			"exit_code": conf.GetInt("exit_code.unauthorized"),
// 		})
// 		return
// 	}
// 	if token != usrToken {
// 		w.WriteHeader(http.StatusUnauthorized)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "unauthorized",
// 			"exit_code": conf.GetInt("exit_code.unauthorized"),
// 		})
// 		return
// 	}
// 	err = cache.SetToRedis(ctx, email.(string), token, 300, redisClient)
// 	if err != nil {
// 		fmt.Println("Set to redis failed:", err)
// 		w.WriteHeader(http.StatusInternalServerError)
// 		w.Header().Set("Content-Type", "application/json")
// 		json.NewEncoder(w).Encode(map[string]interface{}{
// 			"message":   "Set to redis failed",
// 			"exit_code": conf.GetInt("exit_code.internal_error"),
// 		})
// 		return
// 	}
// 	w.WriteHeader(http.StatusOK)
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(map[string]interface{}{
// 		"token":     token,
// 		"exit_code": conf.GetInt("exit_code.success"),
// 	})
// }

func RequestLogger(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.URL.Path)
		handler(w, r)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println(err)
		fmt.Println("err loading: ", err)
	}
	f, err := os.OpenFile("./log.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	log.Println("[+] Starting...")
	if err != nil {
		fmt.Println(err)
		fmt.Println("err loading: ", err)
	}
	http.HandleFunc("/login", RequestLogger(HandleLogin))
	http.HandleFunc("/signup", RequestLogger(HandleSignup))
	// http.HandleFunc("/token/refresh", RequestLogger(HandleRefreshToken))
	// http.HandleFunc("/profile", RequestLogger(account.HandleProfile))

	http.HandleFunc("*", RequestLogger(util.HandleNotFound))
	http.ListenAndServe("127.0.0.1:9080", nil)
}
