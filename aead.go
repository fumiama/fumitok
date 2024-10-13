package fumitok

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

var (
	ErrCipherTextTooShort = errors.New("ciphertext too short")
)

func encode(aead cipher.AEAD, additional uint16, b []byte) []byte {
	nsz := aead.NonceSize()
	// Accocate capacity for all the stuffs.
	buf := make([]byte, 2+nsz+len(b)+aead.Overhead())
	binary.LittleEndian.PutUint16(buf[:2], additional)
	nonce := buf[2 : 2+nsz]
	// Select a random nonce
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	// Encrypt the message and append the ciphertext to the nonce.
	eb := aead.Seal(nonce[nsz:nsz], nonce, b, buf[:2])
	return nonce[:nsz+len(eb)]
}

func decode(aead cipher.AEAD, additional uint16, b []byte) ([]byte, error) {
	nsz := aead.NonceSize()
	if len(b) < nsz {
		return nil, ErrCipherTextTooShort
	}
	// Split nonce and ciphertext.
	nonce, ciphertext := b[:nsz], b[nsz:]
	if len(ciphertext) == 0 {
		return nil, nil
	}
	// Decrypt the message and check it wasn't tampered with.
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], additional)
	return aead.Open(nil, nonce, ciphertext, buf[:])
}
