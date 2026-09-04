package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ckz2json-e2e")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "ckz2json-test")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type runResult struct {
	stdout string
	stderr string
	code   int
}

func runCLI(t *testing.T, dir string, env []string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader("")
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	return runResult{stdout: out.String(), stderr: errb.String(), code: code}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "data.json")
	content := "{\n  \"hello\": \"мир\",\n  \"arr\": [1, 2, 3]\n}\n"
	if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runCLI(t, dir, nil, "-e", "-i", "data.json", "-p", "pass123", "--iter", "2")
	if r.code != 0 {
		t.Fatalf("encrypt failed: %d %s %s", r.code, r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "data.ckz")); err != nil {
		t.Fatalf("data.ckz missing: %v", err)
	}

	r = runCLI(t, dir, nil, "-i", "data.ckz", "-p", "pass123", "-o", "out.json", "-f")
	if r.code != 0 {
		t.Fatalf("decrypt failed: %d %s %s", r.code, r.stdout, r.stderr)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "out.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wantAny, gotAny any
	if err := json.Unmarshal([]byte(content), &wantAny); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &gotAny); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	if len(gotAny.(map[string]any)) != 2 {
		t.Fatalf("content mismatch: %s", raw)
	}
}

func TestCollisionGuard(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.json")
	os.WriteFile(src, []byte(`{"x":1}`), 0o644)
	os.WriteFile(filepath.Join(dir, "a.ckz.junk"), nil, 0o644)

	if r := runCLI(t, dir, nil, "-e", "-i", "a.json", "-p", "p", "--iter", "1"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	r := runCLI(t, dir, nil, "-e", "-i", "a.json", "-p", "p", "--iter", "1")
	if r.code == 0 || !strings.Contains(r.stderr, "уже существует") {
		t.Fatalf("collision not reported: code=%d stderr=%s", r.code, r.stderr)
	}
	if r := runCLI(t, dir, nil, "-e", "-i", "a.json", "-p", "p", "--iter", "1", "-f"); r.code != 0 {
		t.Fatalf("force failed: %s", r.stderr)
	}
}

func TestWrongPassword(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "s.json"), []byte(`{"a":1}`), 0o644)
	runCLI(t, dir, nil, "-e", "-i", "s.json", "-p", "right", "--iter", "1")

	r := runCLI(t, dir, nil, "-i", "s.ckz", "-p", "wrong", "-o", "o.json")
	if r.code != 1 || !strings.Contains(r.stderr, "неверный пароль") {
		t.Fatalf("wrong pw: code=%d out=%s err=%s", r.code, r.stdout, r.stderr)
	}
}

func TestCheckMode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.json"), []byte(`{"a":1}`), 0o644)
	runCLI(t, dir, nil, "-e", "-i", "c.json", "-p", "p", "--iter", "7", "--key-bits", "256", "--tag-bits", "96")

	r := runCLI(t, dir, nil, "-c", "-i", "c.ckz")
	if r.code != 0 {
		t.Fatalf("check failed: %d %s", r.code, r.stderr)
	}
	for _, want := range []string{"записей 1", "iter=7", "ключ=256", "тег=96"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("check output missing %q:\n%s", want, r.stdout)
		}
	}
	// invalid file
	os.WriteFile(filepath.Join(dir, "bad.ckz"), []byte(`{"salt":"zz!!"}`), 0o644)
	r = runCLI(t, dir, nil, "-c", "-i", "bad.ckz")
	if r.code != 1 {
		t.Fatalf("check should fail on bad file: %d", r.code)
	}
}

func TestEnvPasswordAndStdout(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "e.json"), []byte(`{"ok":true}`), 0o644)
	runCLI(t, dir, nil, "-e", "-i", "e.json", "-p", "pw", "--iter", "1")
	r := runCLI(t, dir, []string{"CKZ_PASSWORD=pw"}, "-i", "e.ckz", "--stdout", "-q")
	if r.code != 0 || !json.Valid([]byte(r.stdout)) || !strings.Contains(r.stdout, "ok") {
		t.Fatalf("stdout mode: code=%d out=%s err=%s", r.code, r.stdout, r.stderr)
	}
}

func TestCookiesFormatsAndBatch(t *testing.T) {
	dir := t.TempDir()
	cookiesJSON := `[
	 {"domain":".ex.com","expirationDate":1750000000.9,"hostOnly":false,"httpOnly":false,
	  "name":"id","path":"/","sameSite":"lax","secure":true,"session":false,"value":"v1"},
	 {"domain":"b.org","hostOnly":true,"httpOnly":false,"name":"t","path":"/x",
	  "sameSite":"strict","secure":false,"session":true,"value":"v2"}
	]`
	os.WriteFile(filepath.Join(dir, "c1.json"), []byte(cookiesJSON), 0o644)
	os.WriteFile(filepath.Join(dir, "c2.json"), []byte(cookiesJSON), 0o644)

	r := runCLI(t, dir, nil, "-e", "-p", "b", "--iter", "1", "c1.json", "c2.json")
	if r.code != 0 {
		t.Fatalf("batch encrypt: %s %s", r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "Обработано файлов: 2, с ошибками: 0") {
		t.Fatalf("summary missing: %s", r.stdout)
	}
	for _, f := range []string{"c1.ckz", "c2.ckz"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}

	// decrypt a folder in csv format
	r = runCLI(t, dir, []string{"CKZ_PASSWORD=b"}, "--format", "csv", ".")
	if r.code != 0 {
		t.Fatalf("batch csv: %s %s", r.stdout, r.stderr)
	}
	csvData, err := os.ReadFile(filepath.Join(dir, "c1.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csvData), "id,v1,.ex.com") {
		t.Fatalf("csv content: %s", csvData)
	}
	txtData, _ := os.ReadFile(filepath.Join(dir, "c2.csv"))
	if len(txtData) == 0 {
		t.Fatal("c2.csv not produced")
	}

	// netscape
	if r := runCLI(t, dir, []string{"CKZ_PASSWORD=b"}, "--format", "cookies", "c1.ckz"); r.code != 0 {
		t.Fatalf("netscape: %s %s", r.stdout, r.stderr)
	}
	nets, err := os.ReadFile(filepath.Join(dir, "c1.cookies.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nets), ".ex.com\tTRUE\t/\tTRUE\t1750000000\tid\tv1") {
		t.Fatalf("netscape content: %s", nets)
	}
}

func TestBadFlags(t *testing.T) {
	dir := t.TempDir()
	if r := runCLI(t, dir, nil, "--format", "xml", "-i", "x.ckz"); r.code != 1 || !strings.Contains(r.stderr, "неизвестный формат") {
		t.Fatalf("bad format: %d %s", r.code, r.stderr)
	}
	if r := runCLI(t, dir, nil, "-e", "-c", "-i", "x"); r.code != 1 {
		t.Fatalf("e+c must fail")
	}
}

func TestVersion(t *testing.T) {
	r := runCLI(t, t.TempDir(), nil, "--version")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "ckz2json") {
		t.Fatalf("version: %q", r.stdout)
	}
}

func TestNoArgsWithoutTerminal(t *testing.T) {
	r := runCLI(t, t.TempDir(), nil)
	if r.code != 1 || !strings.Contains(r.stderr, "не указаны входные файлы") {
		t.Fatalf("no-args non-tty: code=%d err=%s", r.code, r.stderr)
	}
}
