//go:build windows

package prompt

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
	procReadConsoleW   = kernel32.NewProc("ReadConsoleW")
)

const (
	enableLineInput = 0x0002
	enableEchoInput = 0x0004
)

// Password reads a password from the console, echoing '*' per character.
func Password(prompt string) (string, error) {
	if !StdinIsTTY() {
		return "", errors.New("нет терминала: передайте пароль флагом -p/--password или переменной CKZ_PASSWORD")
	}
	h := uintptr(syscall.Handle(syscall.Stdin))
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		// Not a real console (e.g. redirected in a strange way): plain read.
		return ReadLine(prompt)
	}
	procSetConsoleMode.Call(h, uintptr(mode&^(enableEchoInput|enableLineInput)))
	defer procSetConsoleMode.Call(h, uintptr(mode))

	fmt.Fprint(os.Stderr, prompt)
	var runes []rune
	var pendingHigh uint16
	buf := make([]uint16, 1)
	for {
		var read uint32
		r, _, err := procReadConsoleW.Call(h, uintptr(unsafe.Pointer(&buf[0])), 1,
			uintptr(unsafe.Pointer(&read)), 0)
		if r == 0 || read == 0 {
			fmt.Fprintln(os.Stderr)
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		c := buf[0]
		switch {
		case c == '\r':
			fmt.Fprintln(os.Stderr)
			return string(runes), nil
		case c == '\n':
			continue
		case c == 0x08: // backspace
			if len(runes) > 0 {
				runes = runes[:len(runes)-1]
				fmt.Fprint(os.Stderr, "\b \b")
			}
			pendingHigh = 0
		case utf16.IsSurrogate(rune(c)):
			if pendingHigh != 0 {
				if dc := utf16.DecodeRune(rune(pendingHigh), rune(c)); dc != 0xFFFD {
					runes = append(runes, dc)
					fmt.Fprint(os.Stderr, "*")
				}
				pendingHigh = 0
			} else {
				pendingHigh = c
			}
		case c >= 0x20:
			pendingHigh = 0
			runes = append(runes, rune(c))
			fmt.Fprint(os.Stderr, "*")
		}
	}
}
