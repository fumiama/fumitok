package fumitok

import (
	"crypto/rand"
	"encoding/hex"
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
		t.Fatal("id", id, "vid", vid, "addt", addt)
	}
	token, err = tk.Generate(id, time.Now().Add(-time.Minute), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)
	_, _, err = tk.Validate(token, 0)
	if err != ErrExpiredToken {
		t.Fatal("unexpected err", err)
	}
}
