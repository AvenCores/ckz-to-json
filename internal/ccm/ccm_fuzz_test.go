package ccm

import "testing"

// FuzzCCM checks that Encrypt/Decrypt are strict inverses and that
// tampering is always detected.
func FuzzCCM(f *testing.F) {
	for _, v := range ccmVectors[:10] {
		f.Add(mustHex(v.key), mustHex(v.nonce), decodeAAD(v.aad), mustHex(v.pt), uint8(v.tagLen))
	}
	f.Fuzz(func(t *testing.T, key, nonce, aad, plain []byte, tagLenB uint8) {
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			t.Skip()
		}
		if len(nonce) < 7 || len(nonce) > 13 || len(plain) > 1<<15 {
			t.Skip()
		}
		tagLen := int(tagLenB)
		if tagLen < 4 || tagLen > 16 || tagLen%2 != 0 {
			t.Skip()
		}
		ct, err := Encrypt(key, nonce, plain, aad, tagLen)
		if err != nil {
			t.Fatalf("Encrypt(%d,%d,%d,%d,%d): %v", len(key), len(nonce), len(aad), len(plain), tagLen, err)
		}
		out, err := Decrypt(key, nonce, ct, aad, tagLen)
		if err != nil {
			t.Fatalf("Decrypt valid input failed: %v", err)
		}
		if string(out) != string(plain) {
			t.Fatal("roundtrip mismatch")
		}
		if len(ct) > 0 {
			bad := make([]byte, len(ct))
			copy(bad, ct)
			bad[0] ^= 0xff
			if _, err := Decrypt(key, nonce, bad, aad, tagLen); err != ErrOpen {
				t.Fatalf("tampered ct must fail with ErrOpen, got: %v", err)
			}
		}
	})
}
