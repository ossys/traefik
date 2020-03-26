package logingov

import (
	"time"
)

type Session struct {
	AuthURL      string
	AccessToken  string
	IdToken      string
	RefreshToken string
	ExpiresAt    time.Time
	CodeVerifier string
}

type UserClaims struct {
	Sub       string `json:"sub"`
	Iss       string `json:"iss"`
	Email     string `json:"email"`
	Token     string `json:"id_token"`
	ExpiresIn int64  `json:"expires_in"`
}

func newUserClaims(tr *TokenResponse, ui *UserInfoResponse) UserClaims {
	return UserClaims{
		Sub:       ui.Sub,
		Iss:       ui.Iss,
		Email:     ui.Email,
		ExpiresIn: tr.ExpiresIn,
		Token:     tr.IdToken,
	}
}

// response from userinfo endpoint
type UserInfoResponse struct {
	Sub           string `json:"sub"`
	Iss           string `json:"iss"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// response from token endpoint
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IdToken     string `json:"id_token"`
}
