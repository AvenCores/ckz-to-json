package ccm

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

type vector struct {
	key    string
	nonce  string
	pt     string
	aad    string
	ct     string
	tagLen int
}

// decodeAAD accepts hex or the "@N" marker for generated pattern bytes.
func decodeAAD(s string) []byte {
	if strings.HasPrefix(s, "@") {
		n, err := strconv.Atoi(s[1:])
		if err != nil {
			panic("bad aad marker: " + s)
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 251)
		}
		return b
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	for i, v := range ccmVectors {
		key := mustHex(v.key)
		nonce := mustHex(v.nonce)
		pt := mustHex(v.pt)
		aad := decodeAAD(v.aad)
		ct := mustHex(v.ct)

		got, err := Encrypt(key, nonce, pt, aad, v.tagLen)
		if err != nil {
			t.Fatalf("vector %d: encrypt: %v", i, err)
		}
		if string(got) != string(ct) {
			t.Fatalf("vector %d: ct mismatch (tag %d, nonce %d, pt %d, aad %d)",
				i, v.tagLen, len(nonce), len(pt), len(aad))
		}

		out, err := Decrypt(key, nonce, ct, aad, v.tagLen)
		if err != nil {
			t.Fatalf("vector %d: decrypt: %v", i, err)
		}
		if string(out) != string(pt) {
			t.Fatalf("vector %d: pt mismatch", i)
		}
	}
}

func TestCorruptedDataRejected(t *testing.T) {
	v := ccmVectors[len(ccmVectors)-1]
	key := mustHex(v.key)
	nonce := mustHex(v.nonce)
	aad := decodeAAD(v.aad)
	ct := mustHex(v.ct)

	badCT := append([]byte(nil), ct...)
	badCT[0] ^= 0xff
	if _, err := Decrypt(key, nonce, badCT, aad, v.tagLen); err == nil {
		t.Fatal("corrupted ciphertext accepted")
	}
	if _, err := Decrypt(key, nonce, ct, append([]byte("x"), aad...), v.tagLen); err == nil {
		t.Fatal("wrong associated data accepted")
	}
	if _, err := Decrypt(key, nonce, ct, aad, v.tagLen); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}

func TestInvalidParameters(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := Encrypt(key, make([]byte, 6), nil, nil, 16); err == nil {
		t.Fatal("short nonce accepted")
	}
	if _, err := Encrypt(key, make([]byte, 14), nil, nil, 16); err == nil {
		t.Fatal("long nonce accepted")
	}
	if _, err := Encrypt(key, nonce, nil, nil, 15); err == nil {
		t.Fatal("odd tag length accepted")
	}
	if _, err := Encrypt(make([]byte, 15), nonce, nil, nil, 16); err == nil {
		t.Fatal("bad key size accepted")
	}
}
