package fumitok

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestTokenizer(t *testing.T) {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		t.Fatal(err)
	}
	tk, err := NewTokenizer(hex.EncodeToString(key[:]))
	if err != nil {
		t.Fatal(err)
	}
	id := uint64(3719371987)
	token, err := tk.Generate(id, time.Now().Add(time.Minute), 0x1234, 0x00ff)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)
	vid, addt, err := tk.Validate(token, 0x00ff)
	if err != nil {
		t.Fatal(err)
	}
	if vid != id || addt != 0x34 {
		t.Fatal("validate id", id, "vid", vid, "addt", addt)
	}
	token2, err := tk.Generate(id, time.Now().Add(-time.Minute), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token2)
	_, _, err = tk.Validate(token2, 0)
	if err != ErrExpiredToken {
		t.Fatal("unexpected err", err)
	}
	token, err = tk.Refresh(token, time.Now().Add(time.Minute), time.Minute*2, 0x00ff)
	if err != nil {
		t.Fatal(err)
	}
	vid, addt, err = tk.Validate(token, 0x00ff)
	if err != nil {
		t.Fatal(err)
	}
	if vid != id || addt != 0x34 {
		t.Fatal("refresh id", id, "vid", vid, "addt", fmt.Sprintf("%02x", addt))
	}
}
