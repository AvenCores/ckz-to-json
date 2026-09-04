//go:build windows

package prompt

// Force UTF-8 console code pages so Russian messages render correctly in
// cmd.exe/PowerShell consoles.
var (
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
)

func init() {
	procSetConsoleOutputCP.Call(65001) // CP_UTF8
	procSetConsoleCP.Call(65001)
}
