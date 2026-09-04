package cookies

import (
	"strings"
	"testing"
)

const chromeExport = `[
  {
    "domain": ".example.com",
    "expirationDate": 1750000000.5,
    "hostOnly": false,
    "httpOnly": true,
    "name": "session",
    "path": "/",
    "sameSite": "no_restriction",
    "secure": true,
    "session": false,
    "storeId": "0",
    "value": "abc123"
  },
  {
    "domain": "test.ru",
    "hostOnly": true,
    "httpOnly": false,
    "name": "sessid",
    "path": "/app",
    "sameSite": "lax",
    "secure": false,
    "session": true,
    "value": "дефг"
  }
]`

func TestFromJSONChromeShape(t *testing.T) {
	cs, err := FromJSON([]byte(chromeExport))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 {
		t.Fatalf("cookies=%d", len(cs))
	}
	if cs[0].Name != "session" || cs[0].Value != "abc123" || !cs[0].Secure || !cs[0].HTTPOnly {
		t.Fatalf("cookie0: %+v", cs[0])
	}
	if !cs[0].HasExpiry || int(cs[0].Expiration) != 1750000000 {
		t.Fatalf("cookie0 expiry: %+v", cs[0])
	}
	if !cs[1].HostOnly || !cs[1].Session || cs[1].Value != "дефг" {
		t.Fatalf("cookie1: %+v", cs[1])
	}
}

func TestFromJSONSingleObjectAndWrapped(t *testing.T) {
	single, err := FromJSON([]byte(`{"name":"a","value":"b","domain":"x.io"}`))
	if err != nil || len(single) != 1 {
		t.Fatalf("single: %d %v", len(single), err)
	}
	wrapped, err := FromJSON([]byte(`{"cookies":[{"name":"a","value":"b","domain":"x.io"}],"meta":1}`))
	if err != nil || len(wrapped) != 1 {
		t.Fatalf("wrapped: %d %v", len(wrapped), err)
	}
}

func TestFromJSONRejectsNonCookies(t *testing.T) {
	for _, in := range []string{`{"a":1}`, `[1,2,3]`, `not json`, `[]`} {
		if _, err := FromJSON([]byte(in)); err == nil {
			t.Fatalf("accepted non-cookies JSON: %s", in)
		}
	}
}

func TestToCSV(t *testing.T) {
	cs, err := FromJSON([]byte(chromeExport))
	if err != nil {
		t.Fatal(err)
	}
	out := string(ToCSV(cs))
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines=%d:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "name,value,domain,path") {
		t.Fatalf("header: %s", lines[0])
	}
	if !strings.Contains(lines[1], "session,abc123,.example.com,/,1750000000.5,true,true,no_restriction") {
		t.Fatalf("row0: %s", lines[1])
	}
	if !strings.Contains(lines[2], `sessid,дефг,test.ru,/app,,false,false,lax`) {
		t.Fatalf("row1: %s", lines[2])
	}
}

func TestToNetscape(t *testing.T) {
	cs, err := FromJSON([]byte(chromeExport))
	if err != nil {
		t.Fatal(err)
	}
	out, err := ToNetscape(cs)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "# Netscape HTTP Cookie File\n") {
		t.Fatalf("header: %q", s)
	}
	if !strings.Contains(s, ".example.com\tTRUE\t/\tTRUE\t1750000000\tsession\tabc123\n") {
		t.Fatalf("row0 missing: %s", s)
	}
	if !strings.Contains(s, "test.ru\tFALSE\t/app\tFALSE\t0\tsessid\tдефг\n") {
		t.Fatalf("row1 missing: %s", s)
	}
}

func TestToNetscapeRequiresDomain(t *testing.T) {
	if _, err := ToNetscape([]Cookie{{Name: "a", Value: "b"}}); err == nil {
		t.Fatal("missing domain accepted")
	}
}
