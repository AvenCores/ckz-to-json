// Package ckz parses CKZ envelopes and decrypts them.
//
// A CKZ record is a JSON object (the file may contain one object or several
// objects, one per line):
//
//	{
//	  "salt":  base64(salt),
//	  "iv":    base64(iv),        // only the first 12 bytes are used as CCM nonce
//	  "ct":    base64(ct||tag),
//	  "adata": utf-8 associated data,
//	  "iter":  PBKDF2 iteration count,
//	  "ks":    key size in bits,
//	  "ts":    tag size in bits
//	}
//
// Key derivation: PBKDF2-HMAC-SHA256(password, salt, iter) -> ks/8 bytes.
// Cipher: AES-CCM(key, tag ts/8) over the first 12 bytes of IV, adata as AAD.
package ckz

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"ckz2json/internal/ccm"
	"ckz2json/internal/kdf"
)

const nonceLen = 12

// ErrDecrypt is returned when authentication fails, which almost always
// means a wrong password or corrupted data.
var ErrDecrypt = ccm.ErrOpen

// Envelope is a single CKZ record.
type Envelope struct {
	Salt  string `json:"salt"`
	IV    string `json:"iv"`
	Ct    string `json:"ct"`
	AData string `json:"adata"`
	Iter  *int   `json:"iter"`
	KS    *int   `json:"ks"`
	TS    *int   `json:"ts"`
}

// ReadRecords decodes all JSON records from r. A single JSON object as well
// as JSON Lines (one object per line) are supported.
func ReadRecords(r io.Reader) ([]*Envelope, error) {
	dec := json.NewDecoder(r)
	var records []*Envelope
	for dec.More() {
		var e Envelope
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("invalid record #%d: %w", len(records)+1, err)
		}
		records = append(records, &e)
	}
	return records, nil
}

// Decrypt derives the key from the password and returns the plaintext.
func (e *Envelope) Decrypt(password []byte) ([]byte, error) {
	if e.Salt == "" || e.Ct == "" {
		return nil, errors.New("ckz: record is missing required fields (salt/iv/ct)")
	}
	if e.Iter == nil || e.KS == nil || e.TS == nil {
		return nil, errors.New("ckz: record is missing iter/ks/ts parameters")
	}
	salt, err := decodeB64(e.Salt)
	if err != nil {
		return nil, fmt.Errorf("ckz: bad base64 in \"salt\": %w", err)
	}
	iv, err := decodeB64(e.IV)
	if err != nil {
		return nil, fmt.Errorf("ckz: bad base64 in \"iv\": %w", err)
	}
	ct, err := decodeB64(e.Ct)
	if err != nil {
		return nil, fmt.Errorf("ckz: bad base64 in \"ct\": %w", err)
	}
	if *e.KS <= 0 || *e.KS%8 != 0 {
		return nil, fmt.Errorf("ckz: invalid key size %d bits", *e.KS)
	}
	if *e.TS <= 0 || *e.TS%8 != 0 {
		return nil, fmt.Errorf("ckz: invalid tag size %d bits", *e.TS)
	}
	nonce := iv
	if len(nonce) > nonceLen {
		nonce = nonce[:nonceLen]
	}
	key, err := kdf.PBKDF2SHA256(password, salt, *e.Iter, *e.KS/8)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return ccm.Decrypt(key, nonce, ct, []byte(e.AData), *e.TS/8)
}

// decodeB64 accepts padded/unpadded and std/url base64 alphabets.
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return base64.StdEncoding.DecodeString(s)
}
