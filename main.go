package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	DB_HOST = "localhost"
	DB_PORT = 5432
	DB_USER = "postgres"
	DB_PASS = "postgres"
	DB_NAME = "userapi"
)

type User struct {
	Id          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Createdtime string `json:"created_at"`
	UpdatedTime string `json:"updated_at"`
}

type UserResponse struct {
	Id          int    `json:"id"`
	Email       string `json:"email"`
	Createdtime string `json:"created_at"`
	UpdatedTime string `json:"updated_at"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

type Credentials struct {
	Password string `json:"password", db:"password"`
	Email    string `json:"email", db:"email"`
}

type secretResponse struct {
	Id     string `json:"user_id"`
	Secret string `json:"secret"`
}

type errorResponse struct {
	Err string `json:"error"`
}

var db *sql.DB

func main() {
	mr := mux.NewRouter()
	mr.HandleFunc("/users", Signup).Methods("POST")
	mr.HandleFunc("/login", Signin).Methods("POST")
	mr.HandleFunc("/secret", Secret).Methods("GET")
	mr.HandleFunc("/users/{id}", Update).Methods("PATCH")

	// initialize our database connection
	err := initDB()
	if err != nil {
		return
	}
	log.Fatal(http.ListenAndServe(":9001", mr))
}

func initDB() error {
	var err error
	// Connect to the postgres db
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME)
	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	return err
}

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func isEmailValid(e string) bool {
	if len(e) < 3 && len(e) > 254 {
		return false
	}
	if !emailRegex.MatchString(e) {
		return false
	}
	parts := strings.Split(e, "@")
	mx, err := net.LookupMX(parts[1])
	if err != nil || len(mx) == 0 {
		return false
	}
	return true
}

func validateUserInput(w http.ResponseWriter, email string, pwd string) bool {
	pass := isEmailValid(email)
	if !pass {
		w.Header().Set("Content-Type", "application/json")
		errResp := errorResponse{Err: "validation error: email"}
		json.NewEncoder(w).Encode(errResp)
	}
	if len(pwd) < 8 {
		w.Header().Set("Content-Type", "application/json")
		errResp := errorResponse{Err: "validation error: password"}
		json.NewEncoder(w).Encode(errResp)
		pass = false
	}

	return pass
}

func Signup(w http.ResponseWriter, r *http.Request) {
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	fmt.Println("AAAAAAAAAA")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !validateUserInput(w, creds.Email, creds.Password) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	storedUser := &User{}
	result := db.QueryRow("select email from users where email=$1", creds.Email)
	err = result.Scan(&storedUser.Email)
	if err != sql.ErrNoRows {
		w.WriteHeader(http.StatusOK)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)

	if _, err = db.Query("insert into users (email, password, createdtime, updatetime) values ($1, $2, $3, $4)", creds.Email, string(hashedPassword), time.Now(), nil); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	result = db.QueryRow("select id from users where email=$1", creds.Email)
	result.Scan(&storedUser.Id)
	result = db.QueryRow("select email from users where email=$1", creds.Email)
	result.Scan(&storedUser.Email)
	result = db.QueryRow("select createdtime from users where email=$1", creds.Email)
	result.Scan(&storedUser.Createdtime)
	result = db.QueryRow("select updatetime from users where email=$1", creds.Email)
	result.Scan(&storedUser.Createdtime)
	if err != nil {
		// If there is an issue with the database, return a 500 error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	user_response := UserResponse{
		Id:          storedUser.Id,
		Email:       storedUser.Email,
		Createdtime: storedUser.Createdtime,
		UpdatedTime: storedUser.UpdatedTime,
	}

	json.NewEncoder(w).Encode(user_response)
}

func GetMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Signin(w http.ResponseWriter, r *http.Request) {
	creds := &Credentials{}

	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !validateUserInput(w, creds.Email, creds.Password) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result := db.QueryRow("select password from users where email=$1", creds.Email)
	if err != nil {
		// If there is an issue with the database, return a 500 error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	storedCreds := &Credentials{}
	// Store the obtained password in `storedCreds`
	err = result.Scan(&storedCreds.Password)
	if err != nil {
		// send an "Unauthorized"(401) status for no user existence
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// generate token and store in DB
	token := GetMD5Hash(strconv.Itoa(rand.Int()))
	if _, err = db.Query("update users set token = $1 where email = $2 ", token, creds.Email); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	token_response := tokenResponse{
		Token: token,
	}

	json.NewEncoder(w).Encode(token_response)
}

func Secret(w http.ResponseWriter, r *http.Request) {

	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer ")
	if len(splitToken) > 1 {
		reqToken = splitToken[1]
		if len(reqToken) < 1 {
			w.Header().Set("Content-Type", "application/json")
			errResp := errorResponse{Err: "token invalid"}
			json.NewEncoder(w).Encode(errResp)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		errResp := errorResponse{Err: "token invalid"}
		json.NewEncoder(w).Encode(errResp)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	result := db.QueryRow("select id from users where token=$1", reqToken)
	storedCreds := &User{}
	err := result.Scan(&storedCreds.Id)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	secret_response := secretResponse{
		Id:     strconv.Itoa(storedCreds.Id),
		Secret: "All your base are belong to us",
	}

	json.NewEncoder(w).Encode(secret_response)
}

func Update(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	id := vars["id"]
	if len(id) < 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	userId, err := strconv.Atoi(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	result := db.QueryRow("select id from users where id=$1", userId)
	storedCreds := &User{}
	err = result.Scan(&storedCreds.Id)
	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	creds := &Credentials{}
	err = json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(creds.Email) > 0 {
		if !isEmailValid(creds.Email) {
			w.Header().Set("Content-Type", "application/json")
			errResp := errorResponse{Err: "validation error: email"}
			json.NewEncoder(w).Encode(errResp)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, err = db.Query("update users set email = $1, updatetime = $2 where id = $3 ", creds.Email, time.Now(), storedCreds.Id); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	if len(creds.Password) > 0 {
		if len(creds.Password) < 8 {
			w.Header().Set("Content-Type", "application/json")
			errResp := errorResponse{Err: "validation error: password"}
			json.NewEncoder(w).Encode(errResp)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)
		if _, err = db.Query("update users set password = $1, updatetime = $2 where id = $3 ", hashedPassword, time.Now(), storedCreds.Id); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	storedUser := &User{}

	result = db.QueryRow("select id from users where id=$1", storedCreds.Id)
	result.Scan(&storedUser.Id)
	result = db.QueryRow("select email from users where id=$1", storedCreds.Id)
	result.Scan(&storedUser.Email)
	result = db.QueryRow("select createdtime from users where id=$1", storedCreds.Id)
	result.Scan(&storedUser.Createdtime)
	result = db.QueryRow("select updatetime from users where id=$1", storedCreds.Id)
	result.Scan(&storedUser.UpdatedTime)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	user_response := UserResponse{
		Id:          storedUser.Id,
		Email:       storedUser.Email,
		Createdtime: storedUser.Createdtime,
		UpdatedTime: storedUser.UpdatedTime,
	}

	json.NewEncoder(w).Encode(user_response)
	return
}
