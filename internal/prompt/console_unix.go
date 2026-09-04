//go:build !windows

package prompt

import "os"

func init() {
	fi, err := os.Stdout.Stat()
	ansiEnabled = err == nil && fi.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
}
