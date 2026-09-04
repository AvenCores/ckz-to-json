//go:build windows

package prompt

import (
	"syscall"
	"unsafe"
)

// Force UTF-8 console code pages so Russian messages render correctly in
// cmd.exe/PowerShell consoles, and enable VT input processing so ANSI
// colors/clearing work in plain cmd.exe windows too (Windows 10+).
var (
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
)

const enableVirtualTerminalProcessing = 0x0004

func init() {
	procSetConsoleOutputCP.Call(65001) // CP_UTF8
	procSetConsoleCP.Call(65001)
	h := uintptr(syscall.Handle(syscall.Stdout))
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r != 0 {
		if r, _, _ := procSetConsoleMode.Call(h, uintptr(mode|enableVirtualTerminalProcessing)); r != 0 {
			ansiEnabled = true
		}
	}
}
