package prompt

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// SGR parameter fragments for Paint.
const (
	Bold     = "1"
	FgRed    = "31"
	FgGreen  = "32"
	FgYellow = "33"
	FgCyan   = "36"
	FgWhite  = "97"
	FgGray   = "90"
)

// ansiEnabled is set from init in console_windows.go / console_unix.go:
// colors are used only when the output really is a capable terminal,
// so piped/redirected output never contains escape sequences.
var ansiEnabled bool

// ANSIEnabled reports whether colored output is available.
func ANSIEnabled() bool { return ansiEnabled }

// Paint wraps s with ANSI SGR codes; returns s unchanged when ANSI is not
// available (piped output, legacy consoles).
func Paint(code, s string) string {
	if !ansiEnabled || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Clear erases the screen and moves the cursor to the top left.
func Clear() {
	if ansiEnabled {
		fmt.Print("\x1b[H\x1b[2J\x1b[3J")
		return
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}
