package ckz

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	payload := []byte(`{"greeting":"привет","n":[1,2,3]}`)
	cases := []struct {
		name string
		p    EncryptParams
	}{
		{"defaults", EncryptParams{Iterations: 3, KeyBits: 256, TagBits: 128}},
		{"key128-tag64", EncryptParams{Iterations: 2, KeyBits: 128, TagBits: 64}},
		{"key192-tag96", EncryptParams{Iterations: 1, KeyBits: 192, TagBits: 96}},
		{"adata", EncryptParams{Iterations: 1, KeyBits: 256, TagBits: 96, AData: "meta:demo"}},
	}
	for _, tc := range cases {
		env, err := Encrypt(payload, []byte("секрет!"), tc.p)
		if err != nil {
			t.Fatalf("%s: Encrypt: %v", tc.name, err)
		}
		records, err := ReadRecords(bytes.NewReader(env))
		if err != nil || len(records) != 1 {
			t.Fatalf("%s: ReadRecords: %v (%d)", tc.name, err, len(records))
		}
		info, err := records[0].Info()
		if err != nil {
			t.Fatalf("%s: Info: %v", tc.name, err)
		}
		if info.KeyBits != tc.p.KeyBits || info.TagBits != tc.p.TagBits || info.Iter != tc.p.Iterations {
			t.Fatalf("%s: Info mismatch: %+v", tc.name, info)
		}
		if info.PayloadLen != len(payload) {
			t.Fatalf("%s: PayloadLen=%d, want %d", tc.name, info.PayloadLen, len(payload))
		}
		plain, err := records[0].Decrypt([]byte("секрет!"))
		if err != nil {
			t.Fatalf("%s: Decrypt: %v", tc.name, err)
		}
		if !bytes.Equal(plain, payload) {
			t.Fatalf("%s: payload mismatch", tc.name)
		}
		if _, err := records[0].Decrypt([]byte("неверный")); err != ErrDecrypt {
			t.Fatalf("%s: wrong password accepted (%v)", tc.name, err)
		}
	}
}

func TestEncryptInvalidParams(t *testing.T) {
	pw := []byte("x")
	for _, p := range []EncryptParams{
		{Iterations: 1, KeyBits: 64, TagBits: 128},
		{Iterations: 1, KeyBits: 256, TagBits: 32},
		{Iterations: 1, KeyBits: 255, TagBits: 128},
	} {
		if _, err := Encrypt([]byte("y"), pw, p); err == nil {
			t.Fatalf("params %+v accepted", p)
		}
	}
}

func TestInfoRejectsGarbage(t *testing.T) {
	e := &Envelope{Salt: "!!!"}
	if _, err := e.Info(); err == nil {
		t.Fatal("envelope without iv/ct accepted")
	}
}
