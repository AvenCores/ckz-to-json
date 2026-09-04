package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type vector struct {
	Password string
	Salt     string // hex
	Iter     int
	DKLen    int
	DK       string // hex
}

func TestPBKDF2Vectors(t *testing.T) {
	if len(pbkdf2Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range pbkdf2Vectors {
		salt, err := hex.DecodeString(v.Salt)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(v.DK)
		if err != nil {
			t.Fatal(err)
		}
		got, err := PBKDF2SHA256([]byte(v.Password), salt, v.Iter, v.DKLen)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("vector %d:\n got %x\nwant %x", i, got, want)
		}
	}
}

func TestInvalidParameters(t *testing.T) {
	if _, err := PBKDF2SHA256([]byte("p"), []byte("s"), 0, 32); err == nil {
		t.Fatal("iterations=0 accepted")
	}
	if _, err := PBKDF2SHA256([]byte("p"), []byte("s"), 1, 0); err == nil {
		t.Fatal("keyLen=0 accepted")
	}
}
