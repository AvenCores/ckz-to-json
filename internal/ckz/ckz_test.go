package ckz

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestSampleFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/sample.ckz")
	if err != nil {
		t.Fatal(err)
	}
	records, err := ReadRecords(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	wantRaw, err := os.ReadFile("../../testdata/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []json.RawMessage
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatal(err)
	}

	for i, rec := range records {
		plain, err := rec.Decrypt([]byte("123"))
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		var got, wantVal any
		if err := json.Unmarshal(plain, &got); err != nil {
			t.Fatalf("record %d: not JSON: %v: %q", i, err, plain)
		}
		if err := json.Unmarshal(want[i], &wantVal); err != nil {
			t.Fatal(err)
		}
		if !jsonEqual(got, wantVal) {
			t.Fatalf("record %d: plaintext mismatch:\n got %s", i, plain)
		}

		if _, err := rec.Decrypt([]byte("wrong-password")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("record %d: wrong password not rejected (%v)", i, err)
		}
	}
}

func TestSingleRecordFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/rec1.ckz")
	if err != nil {
		t.Fatal(err)
	}
	records, err := ReadRecords(bytes.NewReader(data))
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	plain, err := records[0].Decrypt([]byte("123"))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(plain) {
		t.Fatalf("plaintext is not JSON: %q", plain)
	}
}

func TestUnpaddedBase64AndWrongKey(t *testing.T) {
	// raw (unpadded) base64 fields must decode too; decryption with a wrong
	// password must produce ErrDecrypt
	e := &Envelope{
		IV: "AAAAAAAAAAAAAAAA", Ct: "AAAAAAAAAAAAAAAA",
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

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}
