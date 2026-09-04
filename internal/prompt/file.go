package prompt

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// ErrCanceled is returned when the user cancels the selection.
var ErrCanceled = errors.New("выбор отменен")

// File asks the user to pick a file: first via the native OS dialog
// (when running in a terminal and allowed), then via a terminal picker.
// The patterns are glob patterns used by the terminal fallback (first
// pattern is also used as the dialog filter).
func File(noDialog bool, patterns ...string) (string, error) {
	if len(patterns) == 0 {
		patterns = []string{"*.ckz"}
	}
	if !StdinIsTTY() {
		return "", errors.New("нет терминала: укажите файл флагом -i/--in")
	}
	if !noDialog {
		fmt.Fprintln(os.Stderr, Paint(FgGray, fmt.Sprintf("Открывается окно выбора файла %s... Выберите файл в диалоге.", strings.Join(patterns, ", "))))
		p, err := nativeDialog(patterns)
		switch {
		case err == nil:
			return p, nil
		case errors.Is(err, ErrCanceled):
			return "", ErrCanceled
		}
	}
	return pickTerminal(patterns)
}

func nativeDialog(patterns []string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		filter := "All files (*.*)|*.*"
		if len(patterns) > 0 {
			described := make([]string, len(patterns))
			for i, p := range patterns {
				described[i] = strings.ToUpper(strings.TrimPrefix(p, "*.")) + " files (" + p + ")|" + p
			}
			described = append(described, "All files (*.*)|*.*")
			filter = strings.Join(described, "|")
		}
		script := fmt.Sprintf(
			"Add-Type -AssemblyName System.Windows.Forms;"+
				"$f = New-Object System.Windows.Forms.OpenFileDialog;"+
				"$f.Title = 'Выберите файл (%s)'; $f.Filter = '%s';"+
				"if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.FileName; exit 0 } else { exit 3 }",
			strings.Join(patterns, ", "), filter)
		out, err := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-STA", "-Command", script).Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 3 {
				return "", ErrCanceled
			}
			return "", err
		}
		p := CleanPath(string(out))
		if p == "" {
			return "", ErrCanceled
		}
		return p, nil
	case "darwin":
		out, err := exec.Command("osascript", "-e",
			fmt.Sprintf(`POSIX path of (choose file with prompt "Выберите файл (%s)")`, strings.Join(patterns, ", "))).Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() != 0 {
				return "", ErrCanceled
			}
			return "", err
		}
		p := CleanPath(string(out))
		if p == "" {
			return "", ErrCanceled
		}
		return p, nil
	default: // linux & friends: zenity, then kdialog
		if _, err := exec.LookPath("zenity"); err == nil {
			out, err := exec.Command("zenity", "--file-selection",
				fmt.Sprintf("--title=Выберите файл (%s)", strings.Join(patterns, ", ")),
				"--file-filter=Файлы | "+strings.Join(patterns, " ")).Output()
			if err == nil {
				if p := CleanPath(string(out)); p != "" {
					return p, nil
				}
				return "", ErrCanceled
			}
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				return "", ErrCanceled
			}
		}
		if _, err := exec.LookPath("kdialog"); err == nil {
			out, err := exec.Command("kdialog", "--getopenfilename", ".", strings.Join(patterns, " ")).Output()
			if err == nil {
				if p := CleanPath(string(out)); p != "" {
					return p, nil
				}
				return "", ErrCanceled
			}
		}
	}
	return "", errors.New("no native file dialog available")
}

func pickTerminal(patterns []string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	var names []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(cwd, pat))
		if err == nil {
			for _, m := range matches {
				if fi, err := os.Stat(m); err == nil && !fi.IsDir() {
					names = append(names, filepath.Base(m))
				}
			}
		}
	}
	sort.Strings(names)

	if len(names) > 0 {
		fmt.Fprintln(os.Stderr, Paint(FgGray, fmt.Sprintf("Доступные файлы %s в %s:", strings.Join(patterns, ", "), cwd)))
		for i, n := range names {
			fmt.Fprintf(os.Stderr, "  %s %s\n", Paint(Bold+";"+FgYellow, fmt.Sprintf("[%d]", i+1)), n)
		}
	} else {
		fmt.Fprintln(os.Stderr, Paint(FgGray, fmt.Sprintf("В папке %s нет файлов %s", cwd, strings.Join(patterns, ", "))))
	}

	line, err := ReadLine(fmt.Sprintf("Введите номер файла или путь (%s): ", strings.Join(patterns, ", ")))
	if err != nil {
		return "", errors.New("файл не выбран")
	}
	if n, convErr := strconv.Atoi(line); convErr == nil && n >= 1 && n <= len(names) {
		return filepath.Join(cwd, names[n-1]), nil
	}
	p := CleanPath(line)
	if p == "" {
		return "", errors.New("файл не выбран")
	}
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("файл не найден: %s", p)
	}
	return p, nil
}
