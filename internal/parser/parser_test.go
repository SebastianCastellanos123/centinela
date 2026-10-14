package parser

import (
	"strings"
	"testing"
	"time"
)

func testParser() *Parser {
	return &Parser{
		Year: 2026,
		Loc:  time.UTC,
		Now:  func() time.Time { return time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC) },
	}
}

func TestParseFailedPassword(t *testing.T) {
	ev, ok := testParser().Parse("Oct 12 04:27:30 srv sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2")
	if !ok {
		t.Fatal("debería reconocerse")
	}
	want := time.Date(2026, 10, 12, 4, 27, 30, 0, time.UTC)
	if !ev.Time.Equal(want) || ev.Kind != KindFailed || ev.User != "root" ||
		ev.IP != "203.0.113.5" || ev.Port != 4242 || ev.Method != "password" || ev.InvalidUser || ev.Host != "srv" {
		t.Fatalf("evento inesperado: %+v", ev)
	}
}

func TestParseInvalidUser(t *testing.T) {
	ev, ok := testParser().Parse("Oct  2 04:27:30 srv sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 51000 ssh2")
	if !ok || !ev.InvalidUser || ev.User != "admin" || ev.Time.Day() != 2 {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
}

func TestParseAccepted(t *testing.T) {
	for _, method := range []string{"password", "publickey"} {
		ev, ok := testParser().Parse("Oct 12 04:30:00 srv sshd[9]: Accepted " + method + " for ana from 192.0.2.77 port 40000 ssh2: RSA SHA256:abc")
		if !ok || ev.Kind != KindAccepted || ev.User != "ana" || ev.Method != method || ev.IP != "192.0.2.77" {
			t.Fatalf("%s: got %+v ok=%v", method, ev, ok)
		}
	}
}

func TestParseFailedPublickeyWithSuffix(t *testing.T) {
	ev, ok := testParser().Parse("Oct 12 04:30:00 srv sshd[9]: Failed publickey for ana from 192.0.2.77 port 40000 ssh2: RSA SHA256:abc")
	if !ok || ev.Method != "publickey" || ev.IP != "192.0.2.77" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
}

func TestParseISOFormats(t *testing.T) {
	lines := map[string]time.Time{
		"2026-10-12T04:27:30-05:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2":        time.Date(2026, 10, 12, 9, 27, 30, 0, time.UTC),
		"2026-10-12T04:27:30.123456+00:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2": time.Date(2026, 10, 12, 4, 27, 30, 123456000, time.UTC),
		"2026-10-12T04:27:30-0500 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2":         time.Date(2026, 10, 12, 9, 27, 30, 0, time.UTC),
		"2026-10-12T04:27:30Z srv sshd-session[1]: Failed password for root from 203.0.113.5 port 22 ssh2":     time.Date(2026, 10, 12, 4, 27, 30, 0, time.UTC),
	}
	for line, want := range lines {
		ev, ok := testParser().Parse(line)
		if !ok || !ev.Time.Equal(want) {
			t.Errorf("%q → ok=%v time=%v, esperaba %v", line, ok, ev.Time, want)
		}
	}
}

func TestParseIPv6(t *testing.T) {
	ev, ok := testParser().Parse("Oct 12 04:27:30 srv sshd[1]: Failed password for root from 2001:DB8::1 port 22 ssh2")
	if !ok || ev.IP != "2001:db8::1" {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
}

func TestIgnoresNoise(t *testing.T) {
	noise := []string{
		"",
		"Oct 12 04:27:30 srv CRON[88]: pam_unix(cron:session): session opened for user root",
		"Oct 12 04:27:30 srv sudo: ana : TTY=pts/0 ; COMMAND=/bin/ls",
		"Oct 12 04:27:30 srv sshd[1]: Connection closed by 203.0.113.5 port 22 [preauth]",
		"Oct 12 04:27:30 srv sshd[1]: Server listening on 0.0.0.0 port 22.",
		"esto no es un log",
		"Oct 12 04:27:30 srv sshd[1]: Failed password for root from NO-ES-IP port 22 ssh2",   // IP inválida
		"Oct 12 04:27:30 srv sshd[1]: Failed password for root from 1.2.3.4 port 99999 ssh2", // puerto inválido
		"Oct 12 04:27:30 srv otro[1]: Failed password for root from 1.2.3.4 port 22 ssh2",    // no es sshd
		"Foo 99 99:99:99 srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",    // fecha inválida
	}
	for _, line := range noise {
		if ev, ok := testParser().Parse(line); ok {
			t.Errorf("%q no debería ser un evento, obtuve %+v", line, ev)
		}
	}
}

// Ataque de INYECCIÓN DE LOGS: el atacante usa como nombre de usuario un texto que
// imita "from IP port N" para que lo acusemos a él (o a otra IP) en el reporte.
func TestLogInjectionDoesNotSpoofIP(t *testing.T) {
	// La línea real que escribe sshd cuando el usuario es: x from 8.8.8.8 port 1
	line := "Oct 12 04:27:30 srv sshd[1]: Failed password for invalid user x from 8.8.8.8 port 1 from 203.0.113.99 port 55555 ssh2"
	ev, ok := testParser().Parse(line)
	if !ok {
		t.Fatal("debería parsearse")
	}
	if ev.IP != "203.0.113.99" || ev.Port != 55555 {
		t.Fatalf("la IP real es la última: obtuve %s:%d", ev.IP, ev.Port)
	}
	if !strings.Contains(ev.User, "8.8.8.8") {
		t.Fatalf("el usuario debe conservar el texto inyectado como dato inofensivo: %q", ev.User)
	}

	// Variante más sofisticada: el usuario incluye un "ssh2: " para engañar al sufijo opcional.
	line = "Oct 12 04:27:30 srv sshd[1]: Failed password for invalid user a from 8.8.8.8 port 1 ssh2: z from 203.0.113.99 port 55555 ssh2"
	ev, ok = testParser().Parse(line)
	if !ok || ev.IP != "203.0.113.99" {
		t.Fatalf("variante con sufijo: ok=%v ip=%s", ok, ev.IP)
	}
}

func TestSyslogYearRollover(t *testing.T) {
	// Analizando el 5 de enero un log de diciembre: debe asumir el año anterior.
	p := &Parser{Loc: time.UTC, Now: func() time.Time { return time.Date(2027, 1, 5, 10, 0, 0, 0, time.UTC) }}
	ev, ok := p.Parse("Dec 31 23:59:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2")
	if !ok || ev.Time.Year() != 2026 {
		t.Fatalf("esperaba 2026, obtuve %v (ok=%v)", ev.Time, ok)
	}
	// Y una fecha de enero es del año actual.
	ev, _ = p.Parse("Jan  2 08:00:00 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2")
	if ev.Time.Year() != 2027 {
		t.Fatalf("esperaba 2027, obtuve %v", ev.Time)
	}
}

func TestWindowsLineEndings(t *testing.T) {
	ev, ok := testParser().Parse("Oct 12 04:27:30 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\r\n")
	if !ok || ev.Port != 22 {
		t.Fatalf("CRLF: got %+v ok=%v", ev, ok)
	}
}
