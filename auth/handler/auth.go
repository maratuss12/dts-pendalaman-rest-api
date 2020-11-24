package handler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/constant"
	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/database"
	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/helper"
	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/utils"
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
)

type Auth struct {
	Db *gorm.DB
}

func (db *Auth) ValidateAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		utils.WrapAPIError(w, r, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	idUser, role, err := helper.TokenValidation(r)
	if err != nil {
		utils.WrapAPIError(w, r, err.Error(), http.StatusUnauthorized)
		return
	}
	log.Println(idUser)

	utils.WrapAPIData(w, r, database.Auth{
		Username: idUser,
		Role:     &role,
	}, http.StatusOK, "Success Validate!")

	return
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		utils.WrapAPIError(w, r, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	type refreshtoken struct {
		Role         *int   `json:"role" validate:"required"`
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	var rt refreshtoken
	var roleStr string

	if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
		log.Println(err)
		utils.WrapAPIError(w, r, "Error marshalling body", http.StatusInternalServerError)
		return
	}

	if *rt.Role == constant.ADMIN {
		roleStr = "admin"
	} else if *rt.Role == constant.CONSUMER {
		roleStr = "consumer"
	}

	token, err := jwt.Parse(rt.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(fmt.Sprintf("refresh_secret_%s_digitalent", roleStr)), nil
	})

	//TODO SET ENV
	if err != nil {
		utils.WrapAPIError(w, r, "Refresh token expired", http.StatusUnauthorized)
		return
	}

	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		utils.WrapAPIError(w, r, err.Error(), http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims

	if ok && token.Valid {

		idUser, ok := claims["id_user"].(string)
		if !ok {
			utils.WrapAPIError(w, r, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
			return
		}

		err, ts := helper.CreateToken(*rt.Role, idUser)
		if err != nil {
			utils.WrapAPIError(w, r, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}

		utils.WrapAPIData(w, r, tokens, http.StatusOK, "Success refesh token!")
		return
	}
}

func (db *Auth) SignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		utils.WrapAPIError(w, r, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		utils.WrapAPIError(w, r, "can't read body", http.StatusBadRequest)
		return
	}

	var signup database.Auth

	err = json.Unmarshal(body, &signup)
	if err != nil {
		utils.WrapAPIError(w, r, "error unmarshal : "+err.Error(), http.StatusInternalServerError)
		return
	}
	// signup.Token = utils.IdGenerator()

	err = signup.SignUp(db.Db)
	if err != nil {
		utils.WrapAPIError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	utils.WrapAPISuccess(w, r, "Success Sign Up!", http.StatusOK)
}

func (db *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		utils.WrapAPIError(w, r, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		utils.WrapAPIError(w, r, "can't read body", http.StatusBadRequest)
		return
	}

	var login database.Auth

	err = json.Unmarshal(body, &login)
	if err != nil {
		utils.WrapAPIError(w, r, "error unmarshal : "+err.Error(), http.StatusInternalServerError)
		return
	}

	res, err := login.Login(db.Db)
	if err != nil {
		utils.WrapAPIError(w, r, "error unmarshal : "+err.Error(), http.StatusInternalServerError)
		return
	}

	err, token := helper.CreateToken(*res.Role, res.Username)
	utils.WrapAPIData(w, r, token, http.StatusOK, "Success Login!")
	return
}
