// Package ccm implements AES-CCM (NIST SP 800-38C) authentication and
// encryption using only the Go standard library.
package ccm

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"math"
)

// ErrOpen is returned when authentication of the ciphertext fails
// (wrong key/password, corrupted data or associated data).
var ErrOpen = errors.New("ccm: authentication tag mismatch (wrong password or corrupted file)")

const blockSize = aes.BlockSize

// Encrypt returns ciphertext||tag for the given plaintext using AES-CCM.
//
// tagLen must be even and within [4, 16]; nonce must be 7..13 bytes.
func Encrypt(key, nonce, plaintext, adata []byte, tagLen int) ([]byte, error) {
	block, q, err := prepare(key, nonce, plaintext, tagLen)
	if err != nil {
		return nil, err
	}
	mac := cbmac(block, nonce, adata, plaintext, tagLen, q)
	s0 := keystream(block, nonce, q, 0)
	tag := make([]byte, tagLen)
	for i := range tag {
		tag[i] = mac[i] ^ s0[i]
	}
	out := make([]byte, 0, len(plaintext)+tagLen)
	out = append(out, crypt(block, nonce, q, plaintext)...)
	out = append(out, tag...)
	return out, nil
}

// Decrypt verifies and decrypts AES-CCM ciphertext (ciphertext with the
// authentication tag appended). tagLen must be even and within [4, 16];
// nonce must be 7..13 bytes.
func Decrypt(key, nonce, ciphertext, adata []byte, tagLen int) ([]byte, error) {
	if tagLen < 4 || tagLen > 16 || tagLen%2 != 0 {
		return nil, fmt.Errorf("ccm: invalid tag length %d (allowed: 4,6,8,10,12,14,16)", tagLen)
	}
	if len(ciphertext) < tagLen {
		return nil, errors.New("ccm: ciphertext too short")
	}
	body := ciphertext[:len(ciphertext)-tagLen]
	block, q, err := prepare(key, nonce, body, tagLen)
	if err != nil {
		return nil, err
	}
	plaintext := crypt(block, nonce, q, body)
	mac := cbmac(block, nonce, adata, plaintext, tagLen, q)
	s0 := keystream(block, nonce, q, 0)
	for i := 0; i < tagLen; i++ {
		if tag := mac[i] ^ s0[i]; tag != ciphertext[len(ciphertext)-tagLen+i] {
			return nil, ErrOpen
		}
	}
	return plaintext, nil
}

func prepare(key, nonce, msg []byte, tagLen int) (cipher.Block, int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("ccm: invalid key: %w", err)
	}
	if tagLen < 4 || tagLen > 16 || tagLen%2 != 0 {
		return nil, 0, fmt.Errorf("ccm: invalid tag length %d (allowed: 4,6,8,10,12,14,16)", tagLen)
	}
	q := 15 - len(nonce)
	if q < 2 || q > 8 {
		return nil, 0, fmt.Errorf("ccm: invalid nonce length %d (allowed: 7..13)", len(nonce))
	}
	maxMsg := int64(1)<<uint(8*q) - 1
	if q >= 8 {
		maxMsg = math.MaxInt64
	}
	if int64(len(msg)) > maxMsg {
		return nil, 0, errors.New("ccm: message too long for nonce length")
	}
	return block, q, nil
}

// cbmac computes the CBC-MAC over the CCM-format input
// (B0 || adata-blocks || zero-padded plaintext blocks).
func cbmac(block cipher.Block, nonce, adata, msg []byte, tagLen, q int) []byte {
	var x [blockSize]byte
	x[0] = byte(q - 1)
	if len(adata) > 0 {
		x[0] |= 0x40
	}
	x[0] |= byte(((tagLen - 2) / 2) << 3)
	copy(x[1:], nonce)
	for i := 0; i < q; i++ {
		x[16-q+i] = byte(uint64(len(msg)) >> uint(8*(q-1-i)))
	}

	y := make([]byte, blockSize)
	block.Encrypt(y, x[:])

	xorBlock := func(chunk []byte) {
		for i, c := range chunk {
			y[i] ^= c
		}
		block.Encrypt(y, y)
	}

	if len(adata) > 0 {
		var enc []byte
		if len(adata) < 0xff00 {
			enc = []byte{byte(len(adata) >> 8), byte(len(adata))}
		} else {
			enc = []byte{0xff, 0xfe, byte(len(adata) >> 24), byte(len(adata) >> 16),
				byte(len(adata) >> 8), byte(len(adata))}
		}
		buf := make([]byte, 0, len(enc)+len(adata))
		buf = append(buf, enc...)
		buf = append(buf, adata...)
		if r := len(buf) % blockSize; r != 0 {
			buf = append(buf, make([]byte, blockSize-r)...)
		}
		for i := 0; i < len(buf); i += blockSize {
			xorBlock(buf[i : i+blockSize])
		}
	}

	if len(msg) > 0 {
		n := len(msg)
		padded := n
		if r := n % blockSize; r != 0 {
			padded += blockSize - r
		}
		buf := make([]byte, padded)
		copy(buf, msg)
		for i := 0; i < len(buf); i += blockSize {
			xorBlock(buf[i : i+blockSize])
		}
	}
	return y
}

// keystream returns the CTR-mode block A_i encrypted with AES (i = 0 gives
// the mask block used to protect the tag).
func keystream(block cipher.Block, nonce []byte, q int, counter uint64) []byte {
	var a [blockSize]byte
	a[0] = byte(q - 1)
	copy(a[1:], nonce)
	for i := 0; i < q; i++ {
		a[16-q+i] = byte(counter >> uint(8*(q-1-i)))
	}
	s := make([]byte, blockSize)
	block.Encrypt(s, a[:])
	return s
}

// crypt applies the CCM counter-mode keystream (counters 1..n) to the data.
func crypt(block cipher.Block, nonce []byte, q int, in []byte) []byte {
	out := make([]byte, len(in))
	var counter uint64 = 1
	for off := 0; off < len(in); off += blockSize {
		s := keystream(block, nonce, q, counter)
		end := off + blockSize
		if end > len(in) {
			end = len(in)
		}
		for i, b := range in[off:end] {
			out[off+i] = b ^ s[i]
		}
		counter++
	}
	return out
}
