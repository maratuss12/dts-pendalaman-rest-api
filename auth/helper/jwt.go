package helper

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"

	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/constant"
	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/database"
)

// Fungsinya untuk generate token
func CreateToken(role int, idUser string) (error, *database.TokenDetails) {
	var roleStr string

	if role == constant.ADMIN {
		roleStr = "admin"
	} else if role == constant.CONSUMER {
		roleStr = "consumer"
	}

	// Token details initilization
	td := &database.TokenDetails{}
	// Set waktu access token expired
	td.AtExpires = time.Now().Add(time.Second * 10).Unix()
	// Set waktu refresh token expired
	td.RtExpires = time.Now().Add(time.Hour).Unix()

	// Set header + payload access token
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": idUser,
		"role":    role,
		"exp":     td.AtExpires,
	})

	// Set salt access token
	// Admin salt -> secrete_admin_digitalent
	// Consumer salt -> secrete_consumer_digitalent
	var err error
	td.AccessToken, err = at.SignedString([]byte(fmt.Sprintf("secrete_%s_digitalent", roleStr)))
	if err != nil {
		return err, &database.TokenDetails{}
	}

	// Set Header + payload refresh token
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": idUser,
		"role":    role,
		"exp":     td.RtExpires,
	})

	// Set salt refresh token
	// Admin salt -> refresh_secrete_admin_digitalent
	// Consumer salt -> refresh_secrete_consumer_digitalent
	td.RefreshToken, err = rt.SignedString([]byte(fmt.Sprintf("secrete_%s_digitalent", roleStr)))
	if err != nil {
		return err, &database.TokenDetails{}
	}

	return nil, td
}

// Ekstrak data JWT
func ExtractToken(roles int, r *http.Request) string {
	var bearToken string

	if roles == constant.ADMIN {
		bearToken = r.Header.Get("digitalent-admin")
	} else if roles == constant.CONSUMER {
		bearToken = r.Header.Get("digitalent-consumer")
	}

	// Split Bearer xxx_xxx_xxx -> array of string
	// array[0] = Bearer
	// array[1] = xxx_xxx_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}

	return ""
}

// Verifikasi jenis token
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	var roleStr string
	var roles int

	if r.Header.Get("digitalent-admin") != "" {
		roleStr = "admin"
		roles = constant.ADMIN
	} else if r.Header.Get("digitalent-consumer") != "" {
		roleStr = "consumer"
		roles = constant.CONSUMER
	} else {
		return nil, errors.Errorf("Session invalid!")
	}

	tokenString := ExtractToken(roles, r)
	log.Println(tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Cek signing Header apakah HS256
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, errors.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(fmt.Sprintf("secrete_%s_digitalent", roleStr)), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

// Token validation / IsTokenValid summary?
func TokenValidation(r *http.Request) (string, int, error) {
	// Memanggil fungsi verifikasi
	token, err := VerifyToken(r)
	if err != nil {
		return "", 0, err
	}

	// Proses claim payload data dari token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		idUser, ok := claims["id_user"].(string)
		role, ok := claims["role"]
		if !ok {
			return "", 0, nil
		}

		return idUser, int(role.(float64)), nil
	}

	return "", 0, nil
}
