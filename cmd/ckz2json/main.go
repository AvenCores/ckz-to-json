// Command ckz2json decrypts .ckz files and exports their content as JSON.
//
// Decryption: PBKDF2-HMAC-SHA256 password-based key derivation + AES-CCM.
// See internal/ckz for the envelope format description.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ckz2json/internal/ckz"
	"ckz2json/internal/prompt"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		if errors.Is(err, prompt.ErrCanceled) {
			fmt.Fprintln(os.Stderr, "Cancelled.")
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

type config struct {
	input    string
	password string
	output   string
	stdout   bool
	noDialog bool
	force    bool
	quiet    bool
}

func (c *config) parseFlags() bool {
	showVersion := false
	flag.StringVar(&c.input, "i", "", "Path to a .ckz file (if omitted - file selection dialog)")
	flag.StringVar(&c.input, "in", "", "Same as -i")
	flag.StringVar(&c.password, "p", "", "Password (if omitted - hidden prompt or CKZ_PASSWORD env var)")
	flag.StringVar(&c.password, "password", "", "Same as -p")
	flag.StringVar(&c.output, "o", "", "Output .json file (default: <input>.json next to the input)")
	flag.StringVar(&c.output, "out", "", "Same as -o")
	flag.BoolVar(&c.stdout, "stdout", false, "Write the resulting JSON to stdout instead of a file")
	flag.BoolVar(&c.noDialog, "no-dialog", false, "Never open GUI dialogs, pick files in the terminal")
	flag.BoolVar(&c.force, "f", false, "Overwrite the output file if it already exists")
	flag.BoolVar(&c.force, "force", false, "Same as -f")
	flag.BoolVar(&c.quiet, "q", false, "Only report errors")
	flag.BoolVar(&c.quiet, "quiet", false, "Same as -q")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()
	return showVersion
}

func run() error {
	var cfg config
	if cfg.parseFlags() {
		fmt.Println("ckz2json", version)
		return nil
	}

	input, err := resolveInput(&cfg)
	if err != nil {
		return err
	}
	password, err := resolvePassword(&cfg)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	records, err := ckz.ReadRecords(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: %w", input, err)
	}
	if len(records) == 0 {
		return fmt.Errorf("%s: no JSON records found (expected {salt, iv, ct, adata, iter, ks, ts})", input)
	}

	values := make([]json.RawMessage, 0, len(records))
	for i, rec := range records {
		plain, err := rec.Decrypt([]byte(password))
		if err != nil {
			if errors.Is(err, ckz.ErrDecrypt) {
				return fmt.Errorf("record #%d of %s: wrong password or corrupted data", i+1, input)
			}
			return fmt.Errorf("record #%d of %s: %w", i+1, input, err)
		}
		v, err := jsonValue(plain)
		if err != nil {
			return fmt.Errorf("record #%d of %s: %w", i+1, input, err)
		}
		values = append(values, v)
	}

	exported, err := buildExport(values)
	if err != nil {
		return err
	}

	if cfg.stdout {
		os.Stdout.Write(exported)
		os.Stdout.Write([]byte("\n"))
		return nil
	}
	return writeOutput(&cfg, input, exported)
}

func resolveInput(cfg *config) (string, error) {
	if cfg.input != "" {
		p := prompt.CleanPath(cfg.input)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("file not found: %s", p)
		}
		return p, nil
	}
	p, err := prompt.File(cfg.noDialog, "*.ckz")
	if err != nil {
		return "", err
	}
	return p, nil
}

func resolvePassword(cfg *config) (string, error) {
	if cfg.password != "" {
		return cfg.password, nil
	}
	if env := os.Getenv("CKZ_PASSWORD"); env != "" {
		return env, nil
	}
	return prompt.Password("Enter password: ")
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
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func writeOutput(cfg *config, input string, exported []byte) error {
	out := cfg.output
	if out == "" {
		dir, base := filepath.Split(input)
		out = filepath.Join(dir, strings.TrimSuffix(base, filepath.Ext(base))+".json")
		if _, err := os.Stat(out); err == nil && !cfg.force {
			return fmt.Errorf("%s already exists (use -f/--force to overwrite or -o to choose another path)", out)
		}
	}
	if err := os.WriteFile(out, append(exported, '\n'), 0o644); err != nil {
		return err
	}
	if !cfg.quiet {
		fmt.Printf("Exported: %s\n", out)
	}
	return nil
}
