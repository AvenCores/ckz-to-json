package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// PBKDF2-HMAC-SHA256 test vectors (cross-checked against the Python
// `cryptography` package; #1-#4 also match RFC 7914 section 11).
var vectors = []struct {
	password string
	saltHex  string
	dkHex    string
	iter     int
	dkLen    int
}{
	{"password", "73616c74", "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", 1, 32},
	{"password", "73616c74", "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", 2, 32},
	{"password", "73616c74", "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", 4096, 32},
	{"passwordPASSWORDpassword", "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9", 4096, 40},
	{"pass\x00word", "7361006c74", "f9b77371b5a5a07700e7d9cf93dffb8f", 1, 16},
	{"пароль", "d181d0bed0bbd191d0bdd18bd0b92d73616c74", "bcc5284801c963b4942797ec3ddcb729e390ad3b", 1000, 20},
}

func TestPBKDF2Vectors(t *testing.T) {
	for i, v := range vectors {
		salt, err := hex.DecodeString(v.saltHex)
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(v.dkHex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := PBKDF2SHA256([]byte(v.password), salt, v.iter, v.dkLen)
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
