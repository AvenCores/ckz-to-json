// Command ckz2json decrypts/encrypts .ckz files (AES-CCM + PBKDF2-HMAC-SHA256)
// and exports their content as JSON, CSV or Netscape cookies.txt.
//
// The CKZ envelope format documented in internal/ckz is the one used by the
// cookies-backup-chrome browser extension.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ckz2json/internal/ckz"
	"ckz2json/internal/cookies"
	"ckz2json/internal/prompt"
)

var version = "dev"

// errSilent marks failures that were already reported to stderr.
var errSilent = errors.New("ошибки перечислены выше")

func main() {
	err := run()
	if err == nil {
		return
	}
	code := 1
	switch {
	case errors.Is(err, prompt.ErrCanceled):
		code = 2
		fmt.Fprintln(os.Stderr, "Выбор отменен.")
	case errors.Is(err, errSilent):
		// details were printed per file
	default:
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
	}
	prompt.WaitEnter("Нажмите Enter для закрытия... ")
	os.Exit(code)
}

type config struct {
	inputs   multiFlag
	password string
	output   string
	format   string
	adata    string
	iter     int
	keyBits  int
	tagBits  int
	encrypt  bool
	check    bool
	stdout   bool
	noDialog bool
	force    bool
	quiet    bool
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, "; ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func (c *config) parseFlags() bool {
	showVersion := false
	flag.Var(&c.inputs, "i", "Входной файл или папка (можно несколько; без флага - интерактивный выбор)")
	flag.Var(&c.inputs, "in", "То же, что -i")
	flag.StringVar(&c.password, "p", "", "Пароль (иначе - ввод со звездочками или CKZ_PASSWORD)")
	flag.StringVar(&c.password, "password", "", "То же, что -p")
	flag.StringVar(&c.output, "o", "", "Куда сохранить результат (по умолчанию рядом со входом)")
	flag.StringVar(&c.output, "out", "", "То же, что -o")
	flag.StringVar(&c.format, "format", "json", "Формат результата: json | csv | cookies (Netscape cookies.txt)")
	flag.StringVar(&c.adata, "adata", "", "Ассоциированные данные при шифровании (-e)")
	flag.IntVar(&c.iter, "iter", 0, "Итерации PBKDF2 при шифровании (-e), 0 = 100000")
	flag.IntVar(&c.keyBits, "key-bits", 0, "Размер ключа при шифровании: 128/192/256, 0 = 256")
	flag.IntVar(&c.tagBits, "tag-bits", 0, "Размер тега при шифровании: 64/96/128, 0 = 128")
	flag.BoolVar(&c.encrypt, "e", false, "Режим шифрования: .json -> .ckz")
	flag.BoolVar(&c.encrypt, "encrypt", false, "То же, что -e")
	flag.BoolVar(&c.check, "c", false, "Только проверить структуру .ckz (пароль не требуется)")
	flag.BoolVar(&c.check, "check", false, "То же, что -c")
	flag.BoolVar(&c.stdout, "stdout", false, "Вывести результат в stdout вместо файла")
	flag.BoolVar(&c.noDialog, "no-dialog", false, "Не открывать окно выбора файла, выбирать в терминале")
	flag.BoolVar(&c.force, "f", false, "Перезаписывать существующие выходные файлы")
	flag.BoolVar(&c.force, "force", false, "То же, что -f")
	flag.BoolVar(&c.quiet, "q", false, "Выводить только сообщения об ошибках")
	flag.BoolVar(&c.quiet, "quiet", false, "То же, что -q")
	flag.BoolVar(&showVersion, "version", false, "Показать версию и выйти")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Использование: ckz2json [флаги] [входные файлы или папки...]")
		fmt.Fprintln(os.Stderr, "Флаги:")
		flag.PrintDefaults()
	}
	flag.Parse()
	return showVersion
}

func run() error {
	var cfg config
	if cfg.parseFlags() {
		fmt.Println("ckz2json", version)
		return nil
	}

	var err error
	cfg.format, err = normalizeFormat(cfg.format)
	if err != nil {
		return err
	}
	if cfg.encrypt && cfg.check {
		return errors.New("флаги --encrypt и --check несовместимы")
	}
	if cfg.format != formatJSON && (cfg.check || cfg.encrypt) {
		return errors.New("флаг --format применяется только при расшифровке .ckz")
	}
	if cfg.encrypt && cfg.stdout {
		return errors.New("в режиме шифрования --stdout недоступен")
	}

	files := append([]string{}, cfg.inputs...)
	files = append(files, flag.Args()...)
	inputs, err := cfg.resolveInputs(files)
	if err != nil {
		return err
	}

	if cfg.check {
		if !runCheck(&cfg, inputs) {
			return errSilent
		}
		if !cfg.quiet {
			fmt.Println("Все файлы имеют корректную структуру .ckz.")
		}
		prompt.WaitEnter("Нажмите Enter для закрытия... ")
		return nil
	}

	if cfg.password != "" && !cfg.quiet {
		fmt.Fprintln(os.Stderr, "подсказка: пароль в командной строке виден в истории консоли - безопаснее ввести его со звездочками или передать через CKZ_PASSWORD")
	}
	password, err := resolvePassword(&cfg)
	if err != nil {
		return err
	}
	pw := []byte(password)
	defer clear(pw)

	if len(inputs) > 1 && cfg.output != "" {
		return errors.New("при нескольких входных файлах -o/--out не используется - имя результата формируется из имен входов")
	}

	failed := 0
	for _, in := range inputs {
		var err error
		if cfg.encrypt {
			err = encryptFile(&cfg, in, pw)
		} else {
			err = decryptFile(&cfg, in, pw)
		}
		if err == nil {
			continue
		}
		if cfg.stdout || len(inputs) == 1 {
			return err
		}
		failed++
		fmt.Fprintf(os.Stderr, "Ошибка (%s): %v\n", in, err)
	}
	if cfg.stdout {
		return nil
	}
	if !cfg.quiet && len(inputs) > 1 {
		fmt.Printf("Обработано файлов: %d, с ошибками: %d\n", len(inputs), failed)
	}
	if failed > 0 {
		return errSilent
	}
	prompt.WaitEnter("Нажмите Enter для закрытия... ")
	return nil
}

// resolveInputs expands directories and validates existence.
func (cfg *config) resolveInputs(raw []string) ([]string, error) {
	globPattern := "*.ckz"
	if cfg.encrypt {
		globPattern = "*.json"
	}
	if len(raw) == 0 {
		if !prompt.StdinIsTTY() {
			return nil, errors.New("не указаны входные файлы - передайте их аргументами или флагом -i/--in (интерактивный выбор доступен в терминале)")
		}
		sel, err := prompt.File(cfg.noDialog, globPattern)
		if err != nil {
			return nil, err
		}
		raw = []string{sel}
	}
	seen := map[string]bool{}
	var inputs []string
	for _, r := range raw {
		p := prompt.CleanPath(r)
		if strings.HasPrefix(r, "-") {
			return nil, fmt.Errorf("неизвестный аргумент %q - флаги должны стоять перед именами файлов", r)
		}
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("не найдено: %s", p)
		}
		var found []string
		if fi.IsDir() {
			matches, _ := filepath.Glob(filepath.Join(p, globPattern))
			if len(matches) == 0 {
				return nil, fmt.Errorf("в папке %s нет файлов %s", p, globPattern)
			}
			sort.Strings(matches)
			found = append(found, matches...)
		} else {
			found = append(found, p)
		}
		for _, m := range found {
			if !seen[m] {
				seen[m] = true
				inputs = append(inputs, m)
			}
		}
	}
	return inputs, nil
}

func resolvePassword(cfg *config) (string, error) {
	if cfg.password != "" {
		return cfg.password, nil
	}
	if env := os.Getenv("CKZ_PASSWORD"); env != "" {
		return env, nil
	}
	return prompt.Password("Введите пароль: ")
}

// ---- режимы ----

func runCheck(cfg *config, inputs []string) bool {
	ok := true
	for _, in := range inputs {
		records, err := readRecords(in)
		if err != nil {
			ok = false
			fmt.Fprintf(os.Stderr, "%s: %v\n", in, err)
			continue
		}
		if len(records) == 0 {
			ok = false
			fmt.Fprintf(os.Stderr, "%s: не найдены JSON-записи (файл не в формате .ckz?)\n", in)
			continue
		}
		fmt.Printf("%s: записей %d\n", in, len(records))
		for i, rec := range records {
			info, err := rec.Info()
			if err != nil {
				ok = false
				fmt.Printf("  запись #%d: НЕВАЛИДНА - %v\n", i+1, err)
				continue
			}
			fmt.Printf("  запись #%d: OK - PBKDF2 iter=%d, ключ=%d бит, тег=%d бит, salt=%dБ, iv=%dБ, данных=%dБ, adata=%dБ\n",
				i+1, info.Iter, info.KeyBits, info.TagBits, info.SaltLen, info.IVLen, info.PayloadLen, info.ADataLen)
		}
	}
	return ok
}

func encryptFile(cfg *config, in string, pw []byte) error {
	payload, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	data, err := ckz.Encrypt(payload, pw, ckz.EncryptParams{
		Iterations: cfg.iter,
		KeyBits:    cfg.keyBits,
		TagBits:    cfg.tagBits,
		AData:      cfg.adata,
	})
	if err != nil {
		return err
	}
	out, err := cfg.outputPath(in, ".ckz")
	if err != nil {
		return err
	}
	return saveFile(out, append(data, '\n'), cfg.quiet)
}

func decryptFile(cfg *config, in string, pw []byte) error {
	records, err := readRecords(in)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("не найдены JSON-записи (ожидался объект {salt, iv, ct, adata, iter, ks, ts} или JSON-Lines)")
	}

	values := make([]json.RawMessage, 0, len(records))
	cookieBag := make([]cookies.Cookie, 0)
	for i, rec := range records {
		plain, err := rec.Decrypt(pw)
		if err != nil {
			if errors.Is(err, ckz.ErrDecrypt) {
				return fmt.Errorf("запись #%d: неверный пароль или поврежденные данные", i+1)
			}
			return fmt.Errorf("запись #%d: %w", i+1, err)
		}
		if cfg.format != formatJSON {
			cs, err := cookies.FromJSON(plain)
			if err != nil {
				return fmt.Errorf("запись #%d: %w", i+1, err)
			}
			cookieBag = append(cookieBag, cs...)
			continue
		}
		v, err := jsonValue(plain)
		if err != nil {
			return fmt.Errorf("запись #%d: %w", i+1, err)
		}
		values = append(values, v)
	}

	var out []byte
	var ext string
	switch cfg.format {
	case formatJSON:
		ext = ".json"
		out, err = buildExport(values)
	case formatCSV:
		ext = ".csv"
		out = cookies.ToCSV(cookieBag)
	case formatCookies:
		ext = ".cookies.txt"
		out, err = cookies.ToNetscape(cookieBag)
	}
	if err != nil {
		return err
	}
	if cfg.stdout {
		os.Stdout.Write(out)
		return nil
	}
	path, err := cfg.outputPath(in, ext)
	if err != nil {
		return err
	}
	return saveFile(path, out, cfg.quiet)
}

func readRecords(path string) ([]*ckz.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ckz.ReadRecords(bytes.NewReader(data))
}

// ---- вывод ----

const (
	formatJSON    = "json"
	formatCSV     = "csv"
	formatCookies = "cookies"
)

func normalizeFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "json":
		return formatJSON, nil
	case "csv":
		return formatCSV, nil
	case "cookies", "cookies.txt", "netscape":
		return formatCookies, nil
	}
	return "", fmt.Errorf("неизвестный формат %q - доступны json, csv, cookies", s)
}

// outputPath resolves the destination file for a given input.
func (cfg *config) outputPath(in, ext string) (string, error) {
	if cfg.output != "" {
		return cfg.output, nil
	}
	dir, base := filepath.Split(in)
	out := filepath.Join(dir, strings.TrimSuffix(base, filepath.Ext(base))+ext)
	if err := rejectExisting(out, cfg.force); err != nil {
		return "", err
	}
	return out, nil
}

func rejectExisting(out string, force bool) error {
	if !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("файл %s уже существует (перезапись: -f/--force, либо укажите другой путь через -o)", out)
		}
	}
	return nil
}

func saveFile(out string, data []byte, quiet bool) error {
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	if !quiet {
		fmt.Printf("Файл сохранен по пути: %s\n", out)
	}
	return nil
}

// jsonValue turns decrypted bytes into a JSON value: verbatim if the
// plaintext is valid JSON, otherwise as a JSON string.
func jsonValue(plain []byte) (json.RawMessage, error) {
	if json.Valid(plain) {
		return json.RawMessage(plain), nil
	}
	b, err := json.Marshal(string(plain))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// buildExport renders one record as a bare JSON value and several records
// as a JSON array, pretty-printed.
func buildExport(values []json.RawMessage) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	var err error
	if len(values) == 1 {
		err = enc.Encode(values[0])
	} else {
		err = enc.Encode(values)
	}
	if err != nil {
		return nil, err
	}
	return append(bytes.TrimRight(buf.Bytes(), "\n"), '\n'), nil
}
