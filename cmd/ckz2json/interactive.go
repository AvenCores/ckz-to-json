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
	"unicode/utf8"

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
		prompt.Clear()
		drawBanner()
		mode, err := prompt.Choice(h1("выберите режим работы"), []string{
			"расшифровать .ckz         " + hint("-i, -p, --format, -o, --stdout"),
			"зашифровать .json -> .ckz " + hint("-e, --iter, --key-bits, --tag-bits, --adata, -o"),
			"проверить структуру .ckz  " + hint("-c, пароль не потребуется"),
			"выход",
		})
		if err != nil || mode == modeExit {
			return nil
		}
		err = runWizard(mode)
		switch {
		case err == nil, errors.Is(err, errSilent), errors.Is(err, prompt.ErrCanceled):
			// already reported / user aborted the wizard
		default:
			fmt.Fprintln(os.Stderr, "\n"+prompt.Paint(prompt.FgRed, "Ошибка: ")+err.Error())
		}
		prompt.WaitEnter("\n" + hint("нажмите Enter для возврата в меню") + ": ")
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
	step := 0
	next := func(s string) string {
		step++
		return h1(fmt.Sprintf("шаг %d - %s", step, s))
	}

	how, err := prompt.Choice(next("как выбирать входные файлы")+hint("  (--no-dialog)"), []string{
		"окно выбора файла операционной системы (по умолчанию)",
		"нумерованный список в терминале / ручной ввод пути или папки",
	})
	if err != nil {
		return err
	}
	cfg.noDialog = how == 1

	files, err := chooseInputs(cfg.noDialog, glob)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, hint(fmt.Sprintf("выбрано входных файлов: %d", len(files))))

	switch mode {
	case modeDecrypt:
		cfg.format, err = chooseFormat(next("формат результата"))
		if err != nil {
			return err
		}
		if err := chooseOutput(cfg, files, true, next("куда сохранить результат")); err != nil {
			return err
		}
	case modeEncrypt:
		if err := askEncryptParams(cfg, next("параметры шифрования")); err != nil {
			return err
		}
		if err := chooseOutput(cfg, files, false, next("куда сохранить результат")); err != nil {
			return err
		}
	}

	fmt.Fprintln(os.Stderr, next("дополнительные параметры"))
	switch mode {
	case modeDecrypt, modeEncrypt:
		cfg.force, err = prompt.Confirm("перезаписывать существующие выходные файлы? "+hint("(-f)"), false)
		if err != nil {
			return err
		}
	}
	cfg.quiet, err = prompt.Confirm("тихий режим: выводить только ошибки? "+hint("(-q)"), false)
	if err != nil {
		return err
	}

	printSummary(cfg, files)
	start, err := prompt.Confirm(ok("запустить?"), true)
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
		fmt.Fprintln(os.Stderr, ok("  + ")+p)
		more, cerr := prompt.Confirm("добавить ещё файл или целую папку? "+hint("(пакетный режим)"), false)
		if cerr != nil || !more {
			break
		}
	}
	return files, nil
}

func chooseFormat(title string) (string, error) {
	i, err := prompt.Choice(title+hint("  (--format)"), []string{
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
func chooseOutput(cfg *config, files []string, allowStdout bool, title string) error {
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
		labels = append(labels, "вывести в stdout  "+hint("(--stdout)"))
	}
	if len(files) == 1 && !isDir(files[0]) {
		kinds = append(kinds, outManual)
		labels = append(labels, "указать путь вручную  "+hint("(-o/--out)"))
	}
	i, err := prompt.Choice(title, labels)
	if err != nil {
		return err
	}
	switch kinds[i] {
	case outStdout:
		cfg.stdout = true
	case outManual:
		for {
			p := prompt.CleanPath(prompt.Input(hint("  путь к выходному файлу: "), ""))
			if p != "" {
				cfg.output = p
				return nil
			}
			fmt.Fprintln(os.Stderr, prompt.Paint(prompt.FgRed, "  путь не может быть пустым"))
		}
	}
	return nil
}

func isDir(p string) bool {
	fi, err := os.Stat(prompt.CleanPath(p))
	return err == nil && fi.IsDir()
}

// askEncryptParams covers --iter, --key-bits, --tag-bits and --adata.
func askEncryptParams(cfg *config, title string) error {
	fmt.Fprintln(os.Stderr, title+hint("  (--iter, --key-bits, --tag-bits, --adata)"))
	fmt.Fprintln(os.Stderr, hint("  Enter - оставить значение по умолчанию"))
	for {
		s := prompt.Input(hint("  итерации PBKDF2 --iter [100000]: "), "")
		if s == "" {
			break
		}
		n, cerr := strconv.Atoi(s)
		if cerr != nil || n < 1 {
			fmt.Fprintln(os.Stderr, prompt.Paint(prompt.FgRed, "  нужно целое число >= 1"))
			continue
		}
		cfg.iter = n
		break
	}
	i, err := prompt.Choice(hint("  размер ключа --key-bits"), []string{"128", "192", "256 (по умолчанию)"})
	if err != nil {
		return err
	}
	cfg.keyBits = []int{128, 192, 256}[i]
	i, err = prompt.Choice(hint("  размер тега --tag-bits"), []string{"64", "96", "128 (по умолчанию)"})
	if err != nil {
		return err
	}
	cfg.tagBits = []int{64, 96, 128}[i]
	cfg.adata = prompt.Input(hint("  ассоциированные данные --adata [пусто]: "), "")
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
	kv := func(k, v string) {
		pad := 14 - utf8.RuneCountInString(k)
		if pad < 1 {
			pad = 1
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", hint(k+":"), strings.Repeat(" ", pad)+v)
	}
	fmt.Fprintln(os.Stderr, h1("сводка"))
	kv("режим", mode)
	kv("вход", strings.Join(files, "; "))
	if !cfg.check && !cfg.encrypt {
		kv("формат", cfg.format)
	}
	if cfg.check {
		kv("тихий режим", yesNo(cfg.quiet))
		return
	}
	kv("вывод", out)
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
		kv("параметры", fmt.Sprintf("iter=%d, ключ=%d бит, тег=%d бит, adata=%s", iter, keyBits, tagBits, adata))
	}
	kv("перезапись", yesNo(cfg.force))
	kv("тихий режим", yesNo(cfg.quiet))
}
