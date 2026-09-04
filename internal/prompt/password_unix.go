//go:build !windows

package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Password reads a password from the terminal without echoing it.
//
// Echo toggling relies on stty (POSIX terminals); reading happens via
// /dev/tty when possible. If neither is available, falls back to a plain
// line read and warns the user.
func Password(prompt string) (string, error) {
	if !StdinIsTTY() {
		return "", errors.New("no terminal: pass the password with -p/--password or CKZ_PASSWORD")
	}

	echoOff := false
	if state := sttySave(); state != "" {
		if sttySet("-echo") {
			echoOff = true
			defer sttyRestore(state)
		}
	}

	from := os.Stdin
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		from = tty
		fmt.Fprint(tty, prompt)
	} else {
		fmt.Fprint(os.Stderr, prompt)
	}

	line, err := bufio.NewReader(from).ReadString('\n')
	if echoOff {
		fmt.Fprintln(from)
	}
	if err != nil && line == "" {
		return "", err
	}
	if !echoOff {
		fmt.Fprintln(os.Stderr, "warning: password was echoed on screen (echo control unavailable)")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// sttySave returns the saved terminal state from "stty -g" or "" on failure.
func sttySave() string {
	out, err := sttyRun("-g")
	if err != nil {
		return ""
	}
	return out
}

func sttyRestore(state string) {
	sttyRun(strings.FieldsFunc(state, func(r rune) bool {
		return r == ':' || r == ' ' || r == '\t' || r == '\n'
	})...)
}

func sttySet(args ...string) bool {
	_, err := sttyRun(args...)
	return err == nil
}

func sttyRun(args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}
