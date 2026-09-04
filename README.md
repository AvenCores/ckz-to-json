<div align="center">
    <a href="https://www.youtube.com/@avencores/" target="_blank">
      <img src="https://github.com/user-attachments/assets/338bcd74-e3c3-4700-87ab-7985058bd17e" alt="YouTube" height="40">
    </a>
    <a href="https://t.me/avencoresyt" target="_blank">
      <img src="https://github.com/user-attachments/assets/939f8beb-a49a-48cf-89b9-d610ee5c4b26" alt="Telegram" height="40">
    </a>
    <a href="https://vk.ru/avencoresreuploads" target="_blank">
      <img src="https://github.com/user-attachments/assets/dc109dda-9045-4a06-95a5-3399f0e21dc4" alt="VK" height="40">
    </a>
    <a href="https://dzen.ru/avencores" target="_blank">
      <img src="https://github.com/user-attachments/assets/bd55f5cf-963c-4eb8-9029-7b80c8c11411" alt="Dzen" height="40">
    </a>
</div>


# ckz2json

Утилита предназначена для расшифровки файлов `.ckz`, полученных с помощью
расширения Chrome [cookies-backup-chrome](https://github.com/candh/cookies-backup-chrome)
(экспорт cookies с паролем), и экспорта их содержимого в JSON.

Консольная утилита на Go: расшифровывает файлы `.ckz` (AES-CCM + PBKDF2-HMAC-SHA256)
и экспортирует содержимое в JSON. Порт исходного Python-скрипта, переписанный
**только на стандартной библиотеке Go** (без внешних зависимостей, чистый Go —
одинаково собирается под все платформы без C-компилятора).

## Возможности

- выбор `.ckz`-файла: информационное сообщение + диалог выбора файла ОС (Windows / macOS / Linux + zenity/kdialog),
  нумерованный список в терминале, drag&drop пути или флаг `-i`;
- ввод пароля: скрытый ввод с отображением `*` вместо символов, флаг `-p` или переменная `CKZ_PASSWORD`;
- после сохранения JSON выводит путь к файлу и ждет нажатия Enter (окно не закрывается мгновенно
  при запуске двойным кликом);
- AES-CCM (tag 4–16 байт) + PBKDF2-HMAC-SHA256 — та же криптография, что в Python-версии;
- несколько записей в файле (JSON и JSON-Lines) — поддерживаются обе разметки;
- экспорт в человекочитаемый JSON: одна запись — объект, несколько — массив;
  расшифрованный текст, не являющийся JSON, сохраняется как JSON-строка.

## Формат CKZ

```json
{
  "salt":  "base64(salt)",
  "iv":    "base64(iv)",      // как nonce берётся только первые 12 байт
  "ct":    "base64(ciphertext||tag)",
  "adata": "ассоциированные данные (UTF-8)",
  "iter":  100000,            // итераций PBKDF2
  "ks":    256,               // размер ключа, бит
  "ts":    128                // размер аутентификационного тега, бит
}
```

Ключ: `PBKDF2-HMAC-SHA256(password, salt, iter)` длиной `ks/8` байт;
шифр: `AES-CCM(key, tag ts/8)`, nonce = `iv[:12]`, associated data = `adata`.

## Сборка

Требуется Go 1.27+ (внешних зависимостей нет).

```
make build        # текущая платформа -> dist/ckz2json
make release      # linux/darwin/windows × amd64/arm64 -> dist/
make test         # тесты (векторы сверены с Python-библиотекой cryptography)
```

Windows PowerShell — то же самое + сборка zip-архивов:

```powershell
.\build.ps1                     # vet + test + 6 платформ + zip в dist\
.\build.ps1 -Version 1.2.3 -SkipTests
```

Linux/macOS — то же самое + сборка zip-архивов (или tar.gz, если нет `zip`):

```bash
chmod +x build.sh               # если потерялся бит исполнения
./build.sh                      # vet + test + 6 платформ -> dist/
./build.sh 1.2.3                # версия встраивается в бинарник (--version)
```

Бинарникам macOS из unofficial-сборок может потребоваться снятие карантина:
`xattr -d com.apple.quarantine ./ckz2json-darwin-arm64`.

Windows-экземпляры содержат встроенную иконку (`cmd/ckz2json/icon.ico`) и
информацию о программе (свойства файла: название, описание, версия,
правообладание) — ресурсы `cmd/ckz2json/*.syso` закоммичены; после изменения
`cmd/ckz2json/winres.json` или `icon.ico` регенерировать:

```
go run github.com/tc-hib/go-winres@latest make --arch amd64,arm64,386 --in cmd/ckz2json/winres.json --out cmd/ckz2json/winres
```

## Использование

```powershell
# интерактивно: выбрать файл и ввести пароль
# (сначала открывается диалог выбора файла ОС, затем скрытый ввод пароля)
./ckz2json

# файл и пароль параметрами, вывод в stdout
./ckz2json -i data.ckz -p 123 --stdout

# пароль через окружение, выходной файл, перезапись
CKZ_PASSWORD=123 ./ckz2json -i data.ckz --out result.json -f
```

| Флаг | Описание |
|---|---|
| `-i, --in` | путь к `.ckz` (иначе — выбор файла: диалог ОС или терминал) |
| `-p, --password` | пароль (иначе — скрытый ввод или `CKZ_PASSWORD`) |
| `-o, --out` | куда писать JSON (по умолчанию `<имя_входа>.json` рядом с входом) |
| `--stdout` | вывести JSON в stdout вместо файла |
| `--no-dialog` | никогда не открывать GUI-диалоги, выбирать файл в терминале |
| `-f, --force` | перезаписать существующий выходной файл |
| `-q, --quiet` | не выводить сообщения, только ошибки |
| `--version` | версия |

Коды выхода: `0` — успех, `1` — ошибка, `2` — пользователь отменил выбор.

## Крипостойкость/совместимость

Реализация AES-CCM (NIST SP 800-38C) проверена 75+ векторами, сгенерированными
библиотекой Python `cryptography` (AES-128/192/256-CCM; nonce 7–13 байт;
tag 4–16 байт; adata 0–65535 байт), PBKDF2 — векторами RFC 7914 и `cryptography`.
Все тестовые векторы и пример CKZ-записей встроены прямо в `*_test.go`-файлы —
в проекте нет отдельных тестовых данных и генераторов.

Неверный пароль или повреждённые данные всегда отклоняются по аутентификационному
тегу (`record #N: wrong password or corrupted data`) — тихого «мусорного» вывода нет.

## Структура проекта

```
cmd/ckz2json/          CLI: флаги, выбор файла/пароля, экспорт
internal/ccm/          AES-CCM (шифрование/расшифрование) + встроенные векторы
internal/kdf/          PBKDF2-HMAC-SHA256 + встроенные векторы
internal/ckz/          формат конверта CKZ, чтение записей, расшифровка
internal/prompt/       выбор файла (диалоги ОС / терминал) и скрытый ввод пароля
build.sh / build.ps1 / Makefile  кросс-сборки linux/darwin/windows × amd64/arm64
```
# 📜 Лицензия

Проект распространяется под лицензией GPL-3.0. Полный текст лицензии содержится в файле [`LICENSE`](LICENSE).

---
# 💰 Поддержать автора
+ **SBER**: `2202 2050 1464 4675`
