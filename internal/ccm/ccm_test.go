package ccm

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	Key    string `json:"key"`
	Nonce  string `json:"nonce"`
	PT     string `json:"pt"`
	AAD    string `json:"aad"`
	CT     string `json:"ct"`
	TagLen int    `json:"tagLen"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vectors")
	}
	return vs
}

func TestVectors(t *testing.T) {
	for i, v := range loadVectors(t) {
		key, _ := hex.DecodeString(v.Key)
		nonce, _ := hex.DecodeString(v.Nonce)
		pt, _ := hex.DecodeString(v.PT)
		aad, _ := hex.DecodeString(v.AAD)
		ct, _ := hex.DecodeString(v.CT)

		got, err := Encrypt(key, nonce, pt, aad, v.TagLen)
		if err != nil {
			t.Fatalf("vector %d: encrypt: %v", i, err)
		}
		if string(got) != string(ct) {
			t.Fatalf("vector %d: ct mismatch\n got %x\nwant %x", i, got, ct)
		}

		out, err := Decrypt(key, nonce, ct, aad, v.TagLen)
		if err != nil {
			t.Fatalf("vector %d: decrypt: %v", i, err)
		}
		if string(out) != string(pt) {
			t.Fatalf("vector %d: pt mismatch", i)
		}
	}
}

func TestCorruptedDataRejected(t *testing.T) {
	v := loadVectors(t)[6]
	key, _ := hex.DecodeString(v.Key)
	nonce, _ := hex.DecodeString(v.Nonce)
	aad, _ := hex.DecodeString(v.AAD)
	ct, _ := hex.DecodeString(v.CT)

	badCT := append([]byte(nil), ct...)
	badCT[0] ^= 0xff
	if _, err := Decrypt(key, nonce, badCT, aad, v.TagLen); err == nil {
		t.Fatal("corrupted ciphertext accepted")
	}
	if _, err := Decrypt(key, nonce, ct, append([]byte("x"), aad...), v.TagLen); err == nil {
		t.Fatal("wrong associated data accepted")
	}
	if _, err := Decrypt(key, nonce, ct, aad, v.TagLen); err != nil {
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
