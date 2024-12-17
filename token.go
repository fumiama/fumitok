package fumitok

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc64"
	"math/rand"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	TokenLength = 88
)

var (
	ErrInvalidTokenKeySize = errors.New("invalid token key size")
	ErrExpiredToken        = errors.New("expired token")
	ErrInvalidToken        = errors.New("invalid token")
	ErrInvalidTokenLength  = errors.New("invalid token len")
)

// Tokenizer xchacha20 对称加密密钥
type Tokenizer struct {
	aead cipher.AEAD
	tabl *crc64.Table
}

// NewTokenizer ...
func NewTokenizer(hexkeystr string) (t Tokenizer, err error) {
	key, err := hex.DecodeString(hexkeystr)
	if err != nil {
		return
	}
	if len(key) != chacha20poly1305.KeySize {
		err = ErrInvalidTokenKeySize
		return
	}
	t.aead, err = chacha20poly1305.NewX(key)
	if err != nil {
		return
	}
	t.tabl = crc64.MakeTable(crc64.ECMA)
	return
}

// Generate 生成 token
//
//   - id 用户标识符, 被加密
//   - expireAt 有效期至
//   - addt, mask 附加数据和其掩码, 不被加密
func (t *Tokenizer) Generate(id uint64, expireAt time.Time, addt, mask uint16) (string, error) {
	var buf [2 + 8 + 8 + 8]byte
	text := buf[2:]
	binary.LittleEndian.PutUint64(text[:8], uint64(expireAt.UnixMilli()))
	binary.LittleEndian.PutUint64(text[8:16], id)
	h := crc64.New(t.tabl)
	_, err := h.Write(text[:16])
	if err != nil {
		return "", err
	}
	_ = h.Sum(text[16:16])
	addt &= mask
	addt |= (uint16(rand.Uint32()) & (^mask))
	binary.LittleEndian.PutUint16(buf[:2], addt)
	w := bytes.NewBuffer(make([]byte, 0, 64))
	enc := base64.NewEncoder(base64.URLEncoding, w)
	_, err = enc.Write(buf[:2])
	if err != nil {
		return "", err
	}
	_, err = enc.Write(encode(t.aead, addt, text))
	if err != nil {
		return "", err
	}
	err = enc.Close()
	if err != nil {
		return "", err
	}
	return BytesToString(w.Bytes()), nil
}

// Validate 验证并提取信息
//
// # 参数
//   - token 待验证凭据
//   - mask 附加数据之掩码, 将在返回时做掩模
//   - check 在解码前检查附加数据是否符合要求
//
// # 返回
//   - uint64 用户标识符
//   - uint16 附加数据
func (t *Tokenizer) Validate(
	token string, mask uint16, checks ...func(uint16) error,
) (uint64, uint16, time.Time, error) {
	if len(token) != TokenLength {
		return 0, 0, time.Time{}, ErrInvalidTokenLength
	}
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	addt := binary.LittleEndian.Uint16(data[:2])
	addtmsk := addt & mask
	for _, fn := range checks {
		err = fn(addtmsk)
		if err != nil {
			return 0, 0, time.Time{}, err
		}
	}
	data, err = decode(t.aead, addt, data[2:])
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	h := crc64.New(t.tabl)
	_, err = h.Write(data[:16])
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	crc := binary.BigEndian.Uint64(data[16:])
	if crc != h.Sum64() {
		return 0, 0, time.Time{}, ErrInvalidToken
	}
	expireAt := time.UnixMilli(int64(binary.LittleEndian.Uint64(data[:8])))
	if time.Now().After(expireAt) {
		err = ErrExpiredToken
	}
	return binary.LittleEndian.Uint64(data[8:16]), addtmsk, expireAt, err
}

// Refresh 过期时刷新 token
//
//   - token 旧 token
//   - expireAt 新的过期时间
//   - validAfter 旧 token 过期此时间段内仍可用于刷新
//   - mask 附加数据之掩码
//   - check 在解码前检查附加数据是否符合要求
func (t *Tokenizer) Refresh(
	token string, expireAt time.Time, validAfter time.Duration,
	mask uint16, checks ...func(uint16) error,
) (string, error) {
	if len(token) != TokenLength {
		return "", ErrInvalidTokenLength
	}
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	addt := binary.LittleEndian.Uint16(data[:2])
	addtmsk := addt & mask
	for _, fn := range checks {
		err = fn(addtmsk)
		if err != nil {
			return "", err
		}
	}
	data, err = decode(t.aead, addt, data[2:])
	if err != nil {
		return "", err
	}
	h := crc64.New(t.tabl)
	_, err = h.Write(data[:16])
	if err != nil {
		return "", err
	}
	crc := binary.BigEndian.Uint64(data[16:])
	if crc != h.Sum64() {
		return "", ErrInvalidToken
	}
	if time.Now().Add(-validAfter).After( // still invalid even before this time
		time.UnixMilli(int64(binary.LittleEndian.Uint64(data[:8]))),
	) {
		return "", ErrExpiredToken
	}
	return t.Generate(
		binary.LittleEndian.Uint64(data[8:16]),
		expireAt, addtmsk, mask,
	)
}
