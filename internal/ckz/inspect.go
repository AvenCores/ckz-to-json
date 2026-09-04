package ckz

import (
	"errors"
	"fmt"
)

// RecordInfo is a password-independent summary of a record (for --check).
type RecordInfo struct {
	Iter       int
	KeyBits    int
	TagBits    int
	SaltLen    int // bytes
	IVLen      int // bytes
	PayloadLen int // ciphertext length without the tag
	ADataLen   int // bytes of associated data
}

// Info validates the envelope parameters and returns its metadata without
// requiring the password.
func (e *Envelope) Info() (RecordInfo, error) {
	var info RecordInfo
	if e.Salt == "" || e.Ct == "" {
		return info, errors.New("нечитаемая запись: нет полей salt/iv/ct (файл не в формате .ckz?)")
	}
	if e.Iter == nil || e.KS == nil || e.TS == nil {
		return info, errors.New("в записи нет параметров iter/ks/ts")
	}
	if *e.Iter < 1 {
		return info, fmt.Errorf("недопустимое число итераций PBKDF2: %d", *e.Iter)
	}
	if *e.KS%8 != 0 || *e.KS/8 != 16 && *e.KS/8 != 24 && *e.KS/8 != 32 {
		return info, fmt.Errorf("недопустимый размер ключа: %d бит", *e.KS)
	}
	if *e.TS%8 != 0 || *e.TS/8 < 4 || *e.TS/8 > 16 || *e.TS/8%2 != 0 {
		return info, fmt.Errorf("недопустимый размер тега: %d бит", *e.TS)
	}
	salt, err := decodeB64(e.Salt)
	if err != nil {
		return info, fmt.Errorf("некорректный base64 в \"salt\": %w", err)
	}
	iv, err := decodeB64(e.IV)
	if err != nil {
		return info, fmt.Errorf("некорректный base64 в \"iv\": %w", err)
	}
	if len(iv) < 7 || len(iv) > 16 {
		return info, fmt.Errorf("недопустимая длина iv: %d байт", len(iv))
	}
	ct, err := decodeB64(e.Ct)
	if err != nil {
		return info, fmt.Errorf("некорректный base64 в \"ct\": %w", err)
	}
	if len(ct) < *e.TS/8 {
		return info, errors.New("данные короче аутентификационного тега — файл поврежден")
	}
	return RecordInfo{
		Iter:       *e.Iter,
		KeyBits:    *e.KS,
		TagBits:    *e.TS,
		SaltLen:    len(salt),
		IVLen:      len(iv),
		PayloadLen: len(ct) - *e.TS/8,
		ADataLen:   len([]byte(e.AData)),
	}, nil
}
