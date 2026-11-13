// Package turnrest implements the TURN REST (coturn static-auth-secret / RFC 8489 long-term)
// ephemeral credential minting and verification scheme.
package turnrest

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pion/turn/v4"
)

// Credentials is an ephemeral TURN credential pair valid until ExpiresAt.
type Credentials struct {
	Username  string    `json:"username"`
	Password  string    `json:"credential"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Mint issues time-limited TURN REST credentials bound to secret, id, and ttl.
func Mint(secret []byte, id string, now time.Time, ttl time.Duration) (Credentials, error) {
	if len(secret) == 0 {
		return Credentials{}, errors.New("turnrest: empty secret")
	}
	expiresAt := now.UTC().Add(ttl).Truncate(time.Second)
	var username string
	if id == "" {
		username = strconv.FormatInt(expiresAt.Unix(), 10)
	} else {
		username = fmt.Sprintf("%d:%s", expiresAt.Unix(), id)
	}
	return Credentials{
		Username:  username,
		Password:  Password(secret, username),
		ExpiresAt: expiresAt,
	}, nil
}

// Password computes base64(HMAC-SHA1(secret, username)).
func Password(secret []byte, username string) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// ParseExpiry parses the leading Unix timestamp from "<expiry>:<id>" (or "<expiry>").
func ParseExpiry(username string) (int64, bool) {
	if username == "" {
		return 0, false
	}
	head, _, _ := strings.Cut(username, ":")
	ts, err := strconv.ParseInt(head, 10, 64)
	if err != nil {
		return 0, false
	}
	return ts, true
}

// Verify checks expiry against now and derives the Pion HA1 key when still valid.
func Verify(secret []byte, realm, username string, now time.Time) ([]byte, bool) {
	if len(secret) == 0 {
		return nil, false
	}
	expiry, ok := ParseExpiry(username)
	if !ok || now.Unix() > expiry {
		return nil, false
	}
	return turn.GenerateAuthKey(username, realm, Password(secret, username)), true
}
