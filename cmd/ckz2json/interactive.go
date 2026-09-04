package main

// Built-in interactive UI: when the program starts without arguments in a
// terminal, every CLI flag (-i, -p, -o, --format, -e, -c, --iter,
// --key-bits, --tag-bits, --adata, --stdout, --no-dialog, -f, -q) is
// available through a step-by-step menu instead of the command line.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ckz2json/internal/prompt"
)

const (
	modeDecrypt = iota
	modeEncrypt
	modeCheck
	modeExit
)

// runInteractive shows the main menu until the user picks "Выход".
func runInteractive() error {
	for {
		fmt.Printf("=== ckz2json %s ===\n\n", version)
		mode, err := prompt.Choice("Выберите режим:", []string{
			"Расшифровать .ckz (-i, -p, --format, -o, --stdout)",
			"Зашифровать .json -> .ckz (-e, --iter, --key-bits, --tag-bits, --adata, -o)",
			"Проверить структуру .ckz без пароля (-c)",
			"Выход",
		})
		if err != nil || mode == modeExit {
			return nil
		}
		err = runWizard(mode)
		switch {
		case err == nil, errors.Is(err, errSilent), errors.Is(err, prompt.ErrCanceled):
			// already reported / user aborted the wizard
		default:
			fmt.Fprintln(os.Stderr, "Ошибка:", err)
		}
		prompt.WaitEnter("\nНажмите Enter, чтобы вернуться в меню... ")
	}
}

// runWizard asks all questions for one mode and executes the job via execute().
func runWizard(mode int) error {
	cfg := &config{format: formatJSON}
	glob := "*.ckz"
	switch mode {
	case modeEncrypt:
		cfg.encrypt = true
		glob = "*.json"
	case modeCheck:
		cfg.check = true
	}

	useTerminal, err := prompt.Choice("Способ выбора входных файлов (--no-dialog):", []string{
		"окно выбора файла операционной системы (по умолчанию)",
		"нумерованный список в терминале или ввод пути/папки вручную",
	})
	if err != nil {
		return err
	}
	cfg.noDialog = useTerminal == 1

	files, err := chooseInputs(cfg.noDialog, glob)
	if err != nil {
		return err
	}

	switch mode {
	case modeDecrypt:
		cfg.format, err = chooseFormat()
		if err != nil {
			return err
		}
		if err := chooseOutput(cfg, files, true); err != nil {
			return err
		}
	case modeEncrypt:
		if err := askEncryptParams(cfg); err != nil {
			return err
		}
		if err := chooseOutput(cfg, files, false); err != nil {
			return err
		}
	}

	switch mode {
	case modeDecrypt, modeEncrypt:
		cfg.force, err = prompt.Confirm("Перезаписывать существующие выходные файлы (-f)?", false)
		if err != nil {
			return err
		}
	}
	cfg.quiet, err = prompt.Confirm("Тихий режим: выводить только ошибки (-q)?", false)
	if err != nil {
		return err
	}

	printSummary(cfg, files)
	start, err := prompt.Confirm("Запустить?", true)
	if err != nil || !start {
		return nil
	}
	return execute(cfg, files)
}

// chooseInputs collects one or more files/folders, covering repeated -i and
// folder arguments. Cancelling after at least one pick finishes the list.
func chooseInputs(noDialog bool, glob string) ([]string, error) {
	var files []string
	for {
		p, err := prompt.File(noDialog, glob)
		if err != nil {
			if len(files) > 0 {
				break
			}
			return nil, err
		}
		files = append(files, p)
		more, cerr := prompt.Confirm("Добавить ещё файл или целую папку (пакетный режим)?", false)
		if cerr != nil || !more {
			break
		}
	}
	return files, nil
}

func chooseFormat() (string, error) {
	i, err := prompt.Choice("Формат результата (--format):", []string{
		"json - человекочитаемый JSON (по умолчанию)",
		"csv - таблица cookies",
		"cookies - Netscape cookies.txt для импорта в браузер/curl",
	})
	if err != nil {
		return "", err
	}
	switch i {
	case 1:
		return formatCSV, nil
	case 2:
		return formatCookies, nil
	}
	return formatJSON, nil
}

// chooseOutput covers -o/--out and --stdout.
func chooseOutput(cfg *config, files []string, allowStdout bool) error {
	type kind int
	const (
		outDefault kind = iota
		outStdout
		outManual
	)
	kinds := []kind{outDefault}
	labels := []string{"сохранить рядом с входным файлом (по умолчанию)"}
	if allowStdout {
		kinds = append(kinds, outStdout)
		labels = append(labels, "вывести в stdout (--stdout)")
	}
	if len(files) == 1 && !isDir(files[0]) {
		kinds = append(kinds, outManual)
		labels = append(labels, "указать путь вручную (-o/--out)")
	}
	i, err := prompt.Choice("Куда сохранить результат:", labels)
	if err != nil {
		return err
	}
	switch kinds[i] {
	case outStdout:
		cfg.stdout = true
	case outManual:
		for {
			p := prompt.CleanPath(prompt.Input("  путь к выходному файлу (-o): ", ""))
			if p != "" {
				cfg.output = p
				return nil
			}
			fmt.Fprintln(os.Stderr, "  путь не может быть пустым")
		}
	}
	return nil
}

func isDir(p string) bool {
	fi, err := os.Stat(prompt.CleanPath(p))
	return err == nil && fi.IsDir()
}

// askEncryptParams covers --iter, --key-bits, --tag-bits and --adata.
func askEncryptParams(cfg *config) error {
	fmt.Fprintln(os.Stderr, "Параметры шифрования (Enter - значения по умолчанию):")
	for {
		s := prompt.Input("  итерации PBKDF2 --iter [100000]: ", "")
		if s == "" {
			break
		}
		n, cerr := strconv.Atoi(s)
		if cerr != nil || n < 1 {
			fmt.Fprintln(os.Stderr, "  нужно целое число >= 1")
			continue
		}
		cfg.iter = n
		break
	}
	i, err := prompt.Choice("  размер ключа --key-bits:", []string{"128", "192", "256 (по умолчанию)"})
	if err != nil {
		return err
	}
	cfg.keyBits = []int{128, 192, 256}[i]
	i, err = prompt.Choice("  размер тега --tag-bits:", []string{"64", "96", "128 (по умолчанию)"})
	if err != nil {
		return err
	}
	cfg.tagBits = []int{64, 96, 128}[i]
	cfg.adata = prompt.Input("  ассоциированные данные --adata (Enter - пусто): ", "")
	return nil
}

func printSummary(cfg *config, files []string) {
	mode := "расшифровка .ckz"
	switch {
	case cfg.encrypt:
		mode = "шифрование .json -> .ckz"
	case cfg.check:
		mode = "проверка структуры .ckz (пароль не нужен)"
	}
	out := "рядом с входным файлом (расширение зависит от режима)"
	switch {
	case cfg.stdout:
		out = "stdout"
	case cfg.output != "":
		out = cfg.output
	}
	fmt.Fprintf(os.Stderr, "\nСводка:\n  режим:  %s\n  вход:   %s\n", mode, strings.Join(files, "; "))
	if !cfg.check && !cfg.encrypt {
		fmt.Fprintf(os.Stderr, "  формат: %s\n", cfg.format)
	}
	if cfg.check {
		fmt.Fprintf(os.Stderr, "  тихий режим: %s\n\n", yesNo(cfg.quiet))
		return
	}
	fmt.Fprintf(os.Stderr, "  вывод:  %s\n", out)
	if cfg.encrypt {
		iter, keyBits, tagBits := cfg.iter, cfg.keyBits, cfg.tagBits
		if iter == 0 {
			iter = 100000
		}
		if keyBits == 0 {
			keyBits = 256
		}
		if tagBits == 0 {
			tagBits = 128
		}
		adata := cfg.adata
		if adata == "" {
			adata = "(пусто)"
		}
		fmt.Fprintf(os.Stderr, "  iter=%d, ключ=%d бит, тег=%d бит, adata=%s\n", iter, keyBits, tagBits, adata)
	}
	fmt.Fprintf(os.Stderr, "  перезапись (-f): %s\n  тихий режим (-q): %s\n\n", yesNo(cfg.force), yesNo(cfg.quiet))
}

func yesNo(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}
