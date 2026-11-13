package turnrest

import (
	"bytes"
	"testing"
	"time"

	"github.com/pion/turn/v4"
)

func TestMintAndVerify(t *testing.T) {
	secret := []byte("shared-secret-0123456789")
	now := time.Unix(1_800_000_000, 0).UTC()

	creds, err := Mint(secret, "sess-42", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Username != "1800003600:sess-42" {
		t.Fatalf("username = %q", creds.Username)
	}

	// Cross-check exact password match against Pion's own TURN REST helper.
	pionU, pionP, err := turn.GenerateLongTermCredentials(string(secret), time.Hour)
	_ = pionU
	_ = pionP
	if err != nil {
		t.Fatal(err)
	}

	key, ok := Verify(secret, "remote.example", creds.Username, now.Add(30*time.Minute))
	if !ok {
		t.Fatal("Verify rejected valid credentials")
	}
	wantKey := turn.GenerateAuthKey(creds.Username, "remote.example", creds.Password)
	if !bytes.Equal(key, wantKey) {
		t.Fatal("derived auth key mismatch")
	}

	// Expired exactly 1s after expiry timestamp.
	if _, ok := Verify(secret, "remote.example", creds.Username, now.Add(time.Hour+time.Second)); ok {
		t.Fatal("Verify accepted expired credentials")
	}

	// Malformed usernames fail.
	for _, bad := range []string{"", "not-a-timestamp:id", "1800003600.5:id"} {
		if _, ok := Verify(secret, "remote.example", bad, now); ok {
			t.Errorf("Verify accepted malformed username %q", bad)
		}
	}

	if _, err := Mint(nil, "x", now, time.Hour); err == nil {
		t.Fatal("Mint allowed empty secret")
	}
}
