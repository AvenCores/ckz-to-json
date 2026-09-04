// Package prompt provides terminal helpers: file selection and
// hidden password input, using only the Go standard library.
package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// StdinIsTTY reports whether standard input is attached to a terminal.
func StdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ReadLine prints the prompt to stderr and reads one trimmed line from stdin.
func ReadLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// CleanPath removes the surrounding quotes that terminals add on drag&drop.
func CleanPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	return strings.TrimSpace(p)
}

// WaitEnter blocks until Enter is pressed. It does nothing when stdin is
// not a terminal (piped/CI runs).
func WaitEnter(prompt string) {
	if !StdinIsTTY() {
		return
	}
	_, _ = ReadLine(prompt)
}
