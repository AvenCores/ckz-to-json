package ckz

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// Sample CKZ records (JSON Lines) produced with Python cryptography
// (PBKDF2-HMAC-SHA256 + AES-CCM), password "123".
const (
	sampleFile = `{"salt": "di/fscxpCjEUpFXZdnW/oA==", "iv": "PK7EC2ZR2zz9Ie8f/C7pyw==", "ct": "+glOVNWWJHOBD8fliiT+YB2gxPWUWpA2ibnmSiXxySzrhBzDnv/xFIDpmFvCL0vG0mt5llum9TAtLlf8vOnThSYl0TXKxEIugHvKt6ic2gIHCeHBlqbP4w==", "adata": "meta:demo", "iter": 100000, "ks": 256, "ts": 128}
{"salt": "buVy2f91/7+pWWq9mqzMTA==", "iv": "qxGtSeS26t1b2oSP", "ct": "EfSW/E9+WE3yVYD6xt5jS8jXfRSxy+0GefHSQNccmRYY+uDAtM+SONu+WvgdYg==", "adata": "", "iter": 1, "ks": 256, "ts": 64}`

	rec1     = `{"salt": "di/fscxpCjEUpFXZdnW/oA==", "iv": "PK7EC2ZR2zz9Ie8f/C7pyw==", "ct": "+glOVNWWJHOBD8fliiT+YB2gxPWUWpA2ibnmSiXxySzrhBzDnv/xFIDpmFvCL0vG0mt5llum9TAtLlf8vOnThSYl0TXKxEIugHvKt6ic2gIHCeHBlqbP4w==", "adata": "meta:demo", "iter": 100000, "ks": 256, "ts": 128}`
	payload1 = `{"greeting": "привет", "items": [1, 2, 3], "nested": {"ok": true}}`
	payload2 = `{"secret": "second-line", "value": 42}`
)

func TestSampleFile(t *testing.T) {
	records, err := ReadRecords(bytes.NewReader([]byte(sampleFile)))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	for i, rec := range records {
		plain, err := rec.Decrypt([]byte("123"))
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		want := payload1
		if i == 1 {
			want = payload2
		}
		if !json.Valid(plain) {
			t.Fatalf("record %d: plaintext is not JSON: %q", i, plain)
		}
		if !jsonIdentical(plain, []byte(want)) {
			t.Fatalf("record %d: plaintext mismatch", i)
		}
		if _, err := rec.Decrypt([]byte("wrong-password")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("record %d: wrong password not rejected (%v)", i, err)
		}
	}
}

func TestSingleRecord(t *testing.T) {
	records, err := ReadRecords(bytes.NewReader([]byte(rec1)))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	plain, err := records[0].Decrypt([]byte("123"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonIdentical(plain, []byte(payload1)) {
		t.Fatal("plaintext mismatch")
	}
}

func TestUnpaddedBase64AndWrongKey(t *testing.T) {
	e := &Envelope{
		Salt: "AAA", IV: "AAAAAAAAAAAAAAAA", Ct: "AAAAAAAAAAAAAAAA",
		AData: "", Iter: intPtr(1), KS: intPtr(256), TS: intPtr(64),
	}
	for _, salt := range []string{"AAA", "AAAA"} {
		e.Salt = salt
		if _, err := e.Decrypt([]byte("x")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("salt %q: got %v, want ErrDecrypt", salt, err)
		}
	}
}

func intPtr(v int) *int { return &v }

// jsonIdentical compares two JSON documents structurally.
func jsonIdentical(a, b []byte) bool {
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	ab, _ := json.Marshal(va)
	bb, _ := json.Marshal(vb)
	return bytes.Equal(ab, bb)
}
