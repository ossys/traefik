package logingov

import (
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"strings"
)

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func genCodeChallenge(length int) (string, string, error) {
	code, err := randomHex(length)
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256([]byte(code))

	return code, b64.StdEncoding.EncodeToString(sum[:]), nil
}

func hasPrefixInSlice(compare string, list []string) bool {
	for _, item := range list {
		if strings.HasPrefix(compare, item) {
			return true
		}
	}
	return false
}

func loadEmails(filePath string) (map[string]bool, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return make(map[string]bool), err
	}

	emails := strings.Split(string(content), "\n")
	m := make(map[string]bool)
	for _, email := range emails {
		m[email] = true
	}

	return m, nil
}
