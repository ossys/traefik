package logingov

import (
	b64 "encoding/base64"
	"encoding/json"
	"net/http"
)

type CookieOpts struct {
	w        http.ResponseWriter
	name     string
	val      string
	path     string
	domain   string
	maxAge   int
	httpOnly bool
}

func setCookieWithDefaults(w http.ResponseWriter, cookieName string, val string) {
	cookieOpts := CookieOpts{w: w, name: cookieName, val: val}
	setCookieWithOpts(cookieOpts)
}

func setCookieWithOpts(opts CookieOpts) {
	encoded := b64.StdEncoding.EncodeToString([]byte(opts.val))

	maxAge := opts.maxAge
	if maxAge == 0 {
		maxAge = 60 * 60 * 24
	}

	cookie := &http.Cookie{
		MaxAge: maxAge,
		Value:  encoded,

		Name:     opts.name,
		HttpOnly: opts.httpOnly,
		Path:     opts.path,
		Domain:   opts.domain,
	}

	logger.Debug("setting cookie: ", cookie.String())

	http.SetCookie(opts.w, cookie)
	return
}

func getCookie(r *http.Request, cookieName string) (string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", err
	}

	decoded, err := b64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func deleteCookie(w http.ResponseWriter, cookieName, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		MaxAge:   -1,
		Value:    "",
		HttpOnly: false,
		Path:     path,
		Domain:   "ml.ossys.local",
	})
	return
}

func getUserClaimsFromCookie(r *http.Request) (UserClaims, error) {
	val, err := getCookie(r, COOKIE_USER_STORE)
	if err != nil {
		return UserClaims{}, err
	}

	userClaims := UserClaims{}
	err = json.Unmarshal([]byte(val), &userClaims)
	if err != nil {
		return UserClaims{}, err
	}

	return userClaims, nil
}
