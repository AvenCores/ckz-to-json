package prompt

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Choice prints a numbered menu and reads a selection (0-based index into
// options), reprompting until a valid number is entered. On EOF it returns
// ErrCanceled.
func Choice(title string, options []string) (int, error) {
	for {
		fmt.Fprintln(os.Stderr, title)
		for i, o := range options {
			fmt.Fprintf(os.Stderr, "  [%d] %s\n", i+1, o)
		}
		line, err := ReadLine("Выбор: ")
		if err != nil {
			return 0, ErrCanceled
		}
		n, cerr := strconv.Atoi(line)
		if cerr == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		fmt.Fprintf(os.Stderr, "введите число от 1 до %d\n", len(options))
	}
}

// Confirm asks a yes/no question; empty input yields def, EOF yields an
// error so the interactive wizard can abort instead of guessing.
func Confirm(q string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	line, err := ReadLine(q + " " + hint + ": ")
	if err != nil {
		return def, err
	}
	switch strings.ToLower(line) {
	case "y", "yes", "д", "да":
		return true, nil
	case "n", "no", "н", "нет":
		return false, nil
	}
	return def, nil
}

// Input reads one line; empty input or EOF yields def.
func Input(q, def string) string {
	line, err := ReadLine(q)
	if err != nil || line == "" {
		return def
	}
	return line
}
