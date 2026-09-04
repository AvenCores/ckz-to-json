package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

// PBKDF2SHA256 returns keyLen bytes derived from password/salt
// (RFC 8018, PBKDF2 with HMAC-SHA256).
func PBKDF2SHA256(password, salt []byte, iter, keyLen int) ([]byte, error) {
	if iter < 1 {
		return nil, errors.New("kdf: iterations must be >= 1")
	}
	if keyLen < 1 {
		return nil, errors.New("kdf: derived key length must be >= 1")
	}
	return pbkdf2(sha256.New, password, salt, iter, keyLen)
}

func pbkdf2(h func() hash.Hash, password, salt []byte, iter, keyLen int) ([]byte, error) {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf[:], uint32(block))
		prf.Write(buf[:])
		dk = prf.Sum(dk)
		t := dk[len(dk)-hashLen:]
		copy(u, t)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for x := range u {
				t[x] ^= u[x]
			}
		}
	}
	return dk[:keyLen], nil
}
