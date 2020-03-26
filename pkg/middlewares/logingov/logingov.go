package logingov

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/middlewares"
	"github.com/containous/traefik/v2/pkg/tracing"
	"github.com/opentracing/opentracing-go/ext"

	"golang.org/x/oauth2"
)

const (
	TYPE_NAME           = "LoginGov"
	COOKIE_STATE        = "LoginGovOAuthState"
	COOKIE_CODE         = "LoginGovOAuthCode"
	COOKIE_USER_STORE   = "LoginGovOAuthUserStore"
	COOKIE_ORIGINAL_URL = "LoginGovOAuthOriginalUrl"
)

var (
	logger log.Logger
)

// AddPrefix is a middleware used to add prefix to an URL request.
type loginGovHandler struct {
	next   http.Handler
	name   string
	client http.Client

	config       *oauth2.Config
	baseHost     string
	baseUrl      string
	redirectPath string

	userInfoUrl    string
	whitelistPaths []string
	authPaths      []string
	acrValues      string
	loginPath      string
	logoutPath     string

	approvedEmails map[string]bool
}

// New creates a new handler.
func New(ctx context.Context, next http.Handler, config dynamic.LoginGov, name string) (http.Handler, error) {
	logger = log.FromContext(middlewares.GetLoggerCtx(ctx, name, TYPE_NAME))

	config.DefaultValuesIfBlank()

	err := config.CheckValues()
	if err != nil {
		return nil, err
	}

	url, err := url.Parse(config.RedirectUrl)
	if err != nil {
		return nil, errors.New("unable to parse redirectUrl: " + err.Error())

	}
	baseHost := url.Host
	baseUrl := url.Scheme + "://" + url.Host
	redirectPath := url.Path

	var emailFile string
	if len(config.EmailsFile) == 0 {
		emailFile = "/approved-emails.txt"
	}

	approvedEmails, err := loadEmails(emailFile)
	if err != nil {
		return nil, errors.New("Unable to load: " + emailFile)
	}

	scopes := []string{}
	if len(config.Scopes) == 0 {
		scopes = []string{"email"}
	}

	return &loginGovHandler{
		next: next,
		name: name,
		config: &oauth2.Config{
			ClientID:     config.IssuerId,
			ClientSecret: "",
			RedirectURL:  config.RedirectUrl,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.AuthUrl,
				TokenURL: config.TokenUrl,
			},
			Scopes: scopes,
		},
		approvedEmails: approvedEmails,
		baseHost:       baseHost,
		baseUrl:        baseUrl,

		loginPath:    config.LoginPath,
		logoutPath:   config.LogoutPath,
		redirectPath: redirectPath,

		acrValues:   config.AcrValues,
		userInfoUrl: config.UserInfoUrl,

		authPaths:      config.AuthPaths,
		whitelistPaths: config.WhitelistPaths,
	}, nil
}

func (l *loginGovHandler) GetTracingInformation() (string, ext.SpanKindEnum) {
	return l.name, tracing.SpanKindNoneEnum
}

// routing
func (l *loginGovHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Info("serving HTTP")

	l.setOriginCookies(w, r)

	switch {
	case r.URL.Path == l.logoutPath:
		l.serveLogout(w, r)
	case r.URL.Path == l.loginPath:
		l.serveLogin(w, r)
	case r.URL.Path == l.redirectPath:
		l.serveCallback(w, r)
	default:
		l.serveHTTP(w, r)
	}
}

// general handler
func (l *loginGovHandler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Info("Serving (s)erveHTTP: ", r.URL.Path)

	if r.URL.Path == l.loginPath {
		l.serveLogin(w, r)
	}

	for _, _ = range l.authPaths {
		serverPath := r.URL.Path

		logger.Info("whitelisted paths: ", l.whitelistPaths)
		logger.Info("path: ", serverPath)

		if hasPrefixInSlice(string(serverPath), l.whitelistPaths) {
			logger.Info("whitelisted path")
			continue
		}

		userClaims, err := getUserClaimsFromCookie(r)
		if err != nil {
			logger.Error("error retrieving cookie: ", err)
		}

		if userClaims == (UserClaims{}) {
			cookie := &http.Cookie{
				Name:  "origin",
				Value: r.URL.String(),
				Path:  "/",
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, l.loginPath, http.StatusTemporaryRedirect)
			return
		}

		if !l.approvedEmails[userClaims.Email] {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			msg := fmt.Sprintf("Email not authorized: %s", userClaims.Email)

			logger.Error("ERROR: ", msg)
			w.Write([]byte(msg))
			return
		}
	}

	l.next.ServeHTTP(w, r)
}

func (l *loginGovHandler) serveLogin(w http.ResponseWriter, r *http.Request) (int, error) {
	logger.Debug("Serving Login handler")

	state, err := randomHex(32)
	if err != nil {
		return 500, err
	}

	codeVerifier, codeChallenge, err := genCodeChallenge(32)
	if err != nil {
		return 500, err
	}

	authURL, err := l.makeAuthURL(state, codeChallenge, r)
	logger.Debug("auth url: ", authURL)
	if err != nil {
		return 500, err
	}

	cookieOpts := CookieOpts{
		w:      w,
		name:   COOKIE_STATE,
		val:    state,
		domain: l.baseHost,
		maxAge: 60 * 3,
	}
	setCookieWithOpts(cookieOpts)

	cookieOpts = CookieOpts{
		w:      w,
		name:   COOKIE_CODE,
		val:    codeVerifier,
		domain: l.baseHost,
		maxAge: 60 * 3,
	}
	setCookieWithOpts(cookieOpts)

	http.Redirect(w, r, authURL, 303)
	return 200, nil
}

func (l *loginGovHandler) serveCallback(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Serving Callback handler")

	code, ok := r.URL.Query()["code"]
	if !ok {
		err, _ := r.URL.Query()["error"]
		logger.Error("Auth response error: ", err)
		return
	}
	state, ok := r.URL.Query()["state"]
	if !ok || len(state[0]) < 1 {
		logger.Error("State parameter was not supplied")
		return
	}

	original_state, err := getCookie(r, COOKIE_STATE)
	if err != nil {
		logger.Error("Cookie for oauth state not found: %v", err)
		return
	}

	codeVerifier, err := getCookie(r, COOKIE_CODE)
	if err != nil {
		logger.Error("Cookie for oauth code not found: %v", err)
		return
	}

	if original_state != state[0] {
		logger.Error("Original state and received state don't match!")
		http.Redirect(w, r, l.loginPath, 303)
		return
	}

	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code_verifier": {codeVerifier},
		"code":          {code[0]},
	}

	resp, err := http.PostForm(l.config.Endpoint.TokenURL, v)
	if err != nil {
		logger.Error(err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error(err)
		return
	}

	var tokenResponse = new(TokenResponse)
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		logger.Error(err)
		return
	}

	req, err := http.NewRequest("GET", l.userInfoUrl, nil)
	authorization := fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken)
	req.Header.Add("Authorization", authorization)

	resp, err = l.client.Do(req)
	if err != nil {
		logger.Error(err)
		return
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)

	var userInfoResponse = new(UserInfoResponse)
	err = json.Unmarshal(body, &userInfoResponse)
	if err != nil {
		logger.Error(err)
		return
	}

	originalUrl, err := getCookie(r, COOKIE_ORIGINAL_URL)
	if err != nil || originalUrl == "" {
		logger.Error("error getting original url cookie: ", err)
		originalUrl = "/"
	}

	userClaims := newUserClaims(tokenResponse, userInfoResponse)
	json, _ := json.Marshal(userClaims)

	cookieOpts := CookieOpts{w: w, name: COOKIE_USER_STORE, val: string(json), path: "/", domain: l.baseHost}
	setCookieWithOpts(cookieOpts)
	cookieOpts.domain = "mistk.ml.ossys.local"
	setCookieWithOpts(cookieOpts)

	logger.Info("Signed in via login.gov with user: ", userClaims.Email)
	http.Redirect(w, r, originalUrl, 303)

	l.next.ServeHTTP(w, r)
}

func (l *loginGovHandler) serveLogout(w http.ResponseWriter, r *http.Request) (int, error) {
	logger.Debug("Serving Logout Handler")

	userClaims, err := getUserClaimsFromCookie(r)
	msg := "Successfully signed out user."
	if err == nil {
		msg = "Successfully signed out user " + userClaims.Email + "."
	}
	logger.Info(msg)

	deleteCookie(w, COOKIE_STATE, "/oauth/logingov")
	deleteCookie(w, COOKIE_CODE, "/oauth/logingov")
	deleteCookie(w, COOKIE_USER_STORE, "/")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if userClaims != (UserClaims{}) {
		w.Write([]byte("Successfully signed out." + "\n"))
	} else {
		w.Write([]byte("Not signed in or an error occurred." + "\n"))
	}

	w.Write([]byte("<br><br><a href='/'>Home</a>" + "\n"))
	w.WriteHeader(http.StatusOK)
	return 200, nil
}

// Sets an origin cookie for paths other than /oauth/logingov/<etc>.
// Looks for an "X-Origin-Logingov" header, otherwise uses the current path.
func (l *loginGovHandler) setOriginCookies(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/oauth/logingov") {
		return
	}

	originVal := r.Header.Get("X-Origin-Logingov")
	if originVal == "" {
		originVal = r.URL.Path
	}

	cookieOpts := CookieOpts{
		w:      w,
		name:   COOKIE_ORIGINAL_URL,
		val:    originVal,
		domain: l.baseHost,
		path:   "/",
		maxAge: 60 * 3,
	}
	setCookieWithOpts(cookieOpts)

	return
}

// sets up the authorization call to login.gov as per the spec at
// https://developers.login.gov/oidc/#authorization
func (l *loginGovHandler) makeAuthURL(state, codeChallenge string, r *http.Request) (string, error) {
	nonce, err := randomHex(32)
	if err != nil {
		return nonce, err
	}

	scopes := strings.Join(l.config.Scopes, ",")

	var buf bytes.Buffer
	buf.WriteString(l.config.Endpoint.AuthURL + "?")
	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {l.config.ClientID},
		"scope":                 {scopes},
		"redirect_uri":          {l.config.RedirectURL},
		"acr_values":            {l.acrValues},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	buf.WriteString(v.Encode())
	return buf.String(), nil
}
