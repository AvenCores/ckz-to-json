package ckz

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"ckz2json/internal/ccm"
	"ckz2json/internal/kdf"
)

// EncryptParams controls how a payload is encrypted into a CKZ envelope.
type EncryptParams struct {
	Iterations int    // PBKDF2 iteration count (>= 1)
	KeyBits    int    // 128, 192 or 256
	TagBits    int    // 64..128, even, multiple of 16 recommended
	SaltLen    int    // salt length in bytes (default 16 if 0)
	AData      string // associated authenticated data
}

// DefaultEncryptParams matches the parameters used by cookies-backup-chrome.
func DefaultEncryptParams() EncryptParams {
	return EncryptParams{Iterations: 100000, KeyBits: 256, TagBits: 128}
}

// Encrypt derives a key from the password and seals the payload into a
// compact CKZ JSON record (interoperable with Decrypt).
func Encrypt(payload, password []byte, p EncryptParams) ([]byte, error) {
	if p.Iterations < 1 {
		p.Iterations = DefaultEncryptParams().Iterations
	}
	if p.KeyBits == 0 {
		p.KeyBits = 256
	}
	if p.TagBits == 0 {
		p.TagBits = 128
	}
	if p.SaltLen <= 0 {
		p.SaltLen = 16
	}
	if p.KeyBits%8 != 0 || p.KeyBits < 128 || p.KeyBits > 256 {
		return nil, fmt.Errorf("недопустимый размер ключа %d бит (128/192/256)", p.KeyBits)
	}
	if p.TagBits%8 != 0 || p.TagBits < 64 || p.TagBits > 128 {
		return nil, fmt.Errorf("недопустимый размер тега %d бит (64..128)", p.TagBits)
	}

	salt := make([]byte, p.SaltLen)
	iv := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	key, err := kdf.PBKDF2SHA256(password, salt, p.Iterations, p.KeyBits/8)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	ct, err := ccm.Encrypt(key, iv, payload, []byte(p.AData), p.TagBits/8)
	if err != nil {
		return nil, err
	}

	iter, ks, ts := p.Iterations, p.KeyBits, p.TagBits
	env := Envelope{
		Salt:  base64.StdEncoding.EncodeToString(salt),
		IV:    base64.StdEncoding.EncodeToString(iv),
		Ct:    base64.StdEncoding.EncodeToString(ct),
		AData: p.AData,
		Iter:  &iter,
		KS:    &ks,
		TS:    &ts,
	}
	return json.Marshal(&env)
}
