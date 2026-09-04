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

// Password reads a password from the terminal, echoing '*' per character.
//
// Character-at-a-time mode is set up via stty (-echo -icanon min 1);
// reading happens via /dev/tty when possible. If stty is unavailable,
// falls back to a plain line read and warns the user.
func Password(prompt string) (string, error) {
	if !StdinIsTTY() {
		return "", errors.New("нет терминала: передайте пароль флагом -p/--password или переменной CKZ_PASSWORD")
	}

	tty := os.Stdin
	if t, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer t.Close()
		tty = t
	}

	state := sttySave()
	if state == "" || !sttySet("-echo", "-icanon", "min", "1") {
		fmt.Fprint(tty, prompt)
		line, err := bufio.NewReader(tty).ReadString('\n')
		fmt.Fprintln(tty)
		fmt.Fprintln(os.Stderr, "внимание: пароль выводится на экран (stty недоступен)")
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	defer sttyRestore(state)

	fmt.Fprint(tty, prompt)
	r := bufio.NewReader(tty)
	var runes []rune
	for {
		ch, _, err := r.ReadRune()
		if err != nil {
			fmt.Fprintln(tty)
			return "", err
		}
		switch ch {
		case '\n', '\r':
			fmt.Fprintln(tty)
			return string(runes), nil
		case 0x7f, '\b':
			if len(runes) > 0 {
				runes = runes[:len(runes)-1]
				fmt.Fprint(tty, "\b \b")
			}
		default:
			if ch >= 0x20 {
				runes = append(runes, ch)
				fmt.Fprint(tty, "*")
			}
		}
	}
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
