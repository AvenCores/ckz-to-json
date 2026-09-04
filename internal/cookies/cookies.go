// Package cookies converts decrypted cookie exports (as produced by the
// cookies-backup-chrome extension) into CSV and Netscape cookies.txt forms.
package cookies

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Cookie is a normalized cookie record extracted from the JSON export.
type Cookie struct {
	Name       string
	Value      string
	Domain     string
	Path       string
	SameSite   string
	HTTPOnly   bool
	Secure     bool
	Session    bool
	HostOnly   bool
	Expiration float64
	HasExpiry  bool
	RawExtra   map[string]any
}

// FromJSON parses a decrypted payload: a cookie object, an array of cookie
// objects (Chrome cookies.getAll shape) or an object with an "cookies" array.
func FromJSON(data []byte) ([]Cookie, error) {
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("расшифрованный JSON не читается: %w", err)
	}
	arr, ok := asCookieArray(generic)
	if !ok {
		return nil, errors.New("расшифрованный JSON не похож на массив cookies (ожидаются объекты с полями name/value/domain)")
	}
	out := make([]Cookie, 0, len(arr))
	for i, raw := range arr {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("cookie[%d]: ожидается объект", i)
		}
		c, err := fromMap(m)
		if err != nil {
			return nil, fmt.Errorf("cookie[%d]: %w", i, err)
		}
		out = append(out, *c)
	}
	return out, nil
}

func asCookieArray(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		if len(t) > 0 && looksLikeCookie(t[0]) {
			return t, true
		}
	case map[string]any:
		if sub, ok := t["cookies"].([]any); ok && (len(sub) == 0 || looksLikeCookie(sub[0])) {
			return sub, true
		}
		if looksLikeCookie(t) {
			return []any{t}, true
		}
	}
	return nil, false
}

func looksLikeCookie(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, hasName := m["name"]
	_, hasValue := m["value"]
	_, hasDomain := m["domain"]
	return (hasName && hasValue) || (hasName && hasDomain)
}

var cookieKeys = map[string]bool{
	"name": true, "value": true, "domain": true, "path": true,
	"sameSite": true, "httpOnly": true, "secure": true, "session": true,
	"hostOnly": true, "expirationDate": true,
}

func fromMap(m map[string]any) (*Cookie, error) {
	name, _ := m["name"].(string)
	if name == "" {
		return nil, errors.New("нет поля name")
	}
	c := &Cookie{Name: name}
	c.Value, _ = m["value"].(string)
	c.Domain, _ = m["domain"].(string)
	c.Path, _ = m["path"].(string)
	c.HTTPOnly, _ = m["httpOnly"].(bool)
	c.Secure, _ = m["secure"].(bool)
	c.Session, _ = m["session"].(bool)
	c.HostOnly, _ = m["hostOnly"].(bool)
	switch s := m["sameSite"].(type) {
	case string:
		c.SameSite = s
	case float64:
		c.SameSite = strconv.FormatFloat(s, 'f', -1, 64)
	}
	if f, ok := m["expirationDate"].(float64); ok {
		c.Expiration = f
		c.HasExpiry = true
	}
	for k, v := range m {
		if !cookieKeys[k] {
			if c.RawExtra == nil {
				c.RawExtra = map[string]any{}
			}
			c.RawExtra[k] = v
		}
	}
	return c, nil
}

// ToCSV renders cookies as an RFC-4180 CSV table (comma separated, header row).
func ToCSV(cs []Cookie) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"name", "value", "domain", "path", "expirationDate", "httpOnly", "secure", "sameSite"})
	for _, c := range cs {
		exp := ""
		if c.HasExpiry {
			exp = strconv.FormatFloat(c.Expiration, 'f', -1, 64)
		}
		_ = w.Write([]string{
			c.Name, c.Value, c.Domain, strDef(c.Path, "/"), exp,
			strconv.FormatBool(c.HTTPOnly), strconv.FormatBool(c.Secure), c.SameSite,
		})
	}
	w.Flush()
	return buf.Bytes()
}

// ToNetscape renders cookies in the Netscape cookies.txt format used by curl,
// wget, browser imports etc. Records without a domain are skipped-with-error
// only when there is no domain at all.
func ToNetscape(cs []Cookie) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# Netscape HTTP Cookie File\n")
	for i, c := range cs {
		if c.Domain == "" {
			return nil, fmt.Errorf("cookie[%d] (%s): нет поля domain - Netscape-формат не применим", i, c.Name)
		}
		include := "TRUE"
		if c.HostOnly {
			include = "FALSE"
		}
		exp := 0
		if c.HasExpiry && !c.Session {
			exp = int(c.Expiration)
		}
		fmt.Fprintf(&buf, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			c.Domain, include, strDef(c.Path, "/"), boolFlag(c.Secure), exp, c.Name, c.Value)
	}
	return buf.Bytes(), nil
}

func strDef(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func boolFlag(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}
