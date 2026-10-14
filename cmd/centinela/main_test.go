package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	authLog    = "../../testdata/auth.log"
	journalLog = "../../testdata/journal-iso.log"
)

var base = []string{"-year", "2026", "-tz", "UTC"}

func exec(t *testing.T, stdin string, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(context.Background(), args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestAnalyzesSampleLog(t *testing.T) {
	code, out, _ := exec(t, "", append(base, authLog)...)
	if code != 0 {
		t.Fatalf("código %d", code)
	}
	for _, want := range []string{
		"CRÍTICA", "Acceso exitoso tras fallos", `Entró como "deploy"`, // compromiso
		"203.0.113.50", "Intentos: 45", // fuerza bruta contra root
		"Rociado de contraseñas", "198.51.100.23",
		"Ataque lento", "203.0.113.200", // el escaneo lento
		"2001:db8:abcd::17", // IPv6
	} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en el informe", want)
		}
	}
	// Seguridad: ni escapes de terminal ni IPs falsificadas por inyección de logs.
	if strings.Contains(out, "\x1b") {
		t.Error("el informe contiene secuencias de escape del atacante")
	}
	if strings.Contains(out, "IP: 8.8.8.8") {
		t.Error("la inyección de logs logró acusar a 8.8.8.8")
	}
	// Los usuarios legítimos no generan alertas.
	for _, innocent := range []string{"IP: 10.0.0.5", "IP: 10.0.0.6"} {
		if strings.Contains(out, innocent) {
			t.Errorf("falso positivo: %s", innocent)
		}
	}
}

func TestJSONFormat(t *testing.T) {
	code, out, _ := exec(t, "", append(base, "-format", "json", authLog)...)
	var rep struct {
		Failed int `json:"failed"`
		Alerts []struct {
			Rule, Severity, IP string
		}
	}
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil {
		t.Fatalf("JSON inválido (código %d): %s", code, out)
	}
	if rep.Failed != 108 {
		t.Errorf("fallos = %d, esperaba 108 (45+12+6+30+7+7+1)", rep.Failed)
	}
	if rep.Alerts[0].Severity != "critical" || rep.Alerts[0].Rule != "success_after_failures" {
		t.Errorf("la primera alerta debe ser la crítica: %+v", rep.Alerts[0])
	}
}

func TestMarkdownFormat(t *testing.T) {
	_, out, _ := exec(t, "", append(base, "-format", "markdown", authLog)...)
	if !strings.Contains(out, "# Informe de accesos SSH") || !strings.Contains(out, "| crítica |") {
		t.Fatalf("markdown inesperado:\n%s", out)
	}
}

func TestISOFormatAndCompromise(t *testing.T) {
	code, out, _ := exec(t, "", "-fail-on", "critical", journalLog)
	if code != 2 {
		t.Fatalf("hay una alerta crítica: esperaba código 2, obtuve %d\n%s", code, out)
	}
	if !strings.Contains(out, "203.0.113.60") || !strings.Contains(out, `"root"`) {
		t.Fatalf("salida:\n%s", out)
	}
}

func TestFailOnExitCodes(t *testing.T) {
	cases := []struct {
		failOn string
		want   int
	}{{"none", 0}, {"medium", 2}, {"high", 2}, {"critical", 2}}
	for _, c := range cases {
		if code, _, _ := exec(t, "", append(base, "-fail-on", c.failOn, authLog)...); code != c.want {
			t.Errorf("-fail-on %s: código %d, esperaba %d", c.failOn, code, c.want)
		}
	}
	// Un log limpio nunca falla.
	clean := "Oct 12 08:00:00 srv sshd[1]: Accepted publickey for ana from 10.0.0.5 port 4000 ssh2\n"
	if code, out, _ := exec(t, clean, append(base, "-fail-on", "medium", "-")...); code != 0 || !strings.Contains(out, "Sin alertas") {
		t.Errorf("log limpio: código %d\n%s", code, out)
	}
}

func TestStdinAndGzip(t *testing.T) {
	raw, err := os.ReadFile(authLog)
	if err != nil {
		t.Fatal(err)
	}
	_, fromStdin, _ := exec(t, string(raw), append(base, "-")...)

	gzPath := filepath.Join(t.TempDir(), "auth.log.1.gz")
	f, _ := os.Create(gzPath)
	zw := gzip.NewWriter(f)
	zw.Write(raw)
	zw.Close()
	f.Close()
	_, fromGz, _ := exec(t, "", append(base, gzPath)...)

	_, fromFile, _ := exec(t, "", append(base, authLog)...)
	if fromStdin != fromFile || fromGz != fromFile {
		t.Fatal("stdin, .gz y archivo normal deben dar el mismo informe")
	}
}

func TestThresholdsAreConfigurable(t *testing.T) {
	// Con umbral de 100 fallos la fuerza bruta de 45 intentos ya no alerta.
	_, out, _ := exec(t, "", append(base, "-brute", "100", "-slow", "-1", "-spray", "100", authLog)...)
	if strings.Contains(out, "IP: 203.0.113.50") {
		t.Fatal("con -brute 100 no debía alertar")
	}
	if !strings.Contains(out, "Acceso exitoso tras fallos") {
		t.Fatal("la regla de compromiso sigue activa")
	}
}

func TestOutOfOrderFilesWarn(t *testing.T) {
	// Pasar el archivo más reciente primero y el antiguo después.
	_, _, errOut := exec(t, "", append(base, authLog, journalLog)...)
	// journal-iso es de la madrugada (UTC-5 → 08:xx UTC); authLog termina a las 18h → fuera de orden.
	if !strings.Contains(errOut, "fuera de orden") {
		t.Fatalf("esperaba aviso de orden cronológico, stderr=%q", errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := map[string][]string{
		"sin archivos":     {},
		"formato inválido": {"-format", "xml", authLog},
		"fail-on inválido": {"-fail-on", "banana", authLog},
		"zona inválida":    {"-tz", "Marte/Olimpo", authLog},
		"archivo faltante": {"no-existe.log"},
		"-f con stdin":     {"-f", "-"},
		"flag desconocido": {"-nope", authLog},
	}
	for name, args := range cases {
		if code, _, _ := exec(t, "", args...); code != 1 {
			t.Errorf("%s: código %d, esperaba 1", name, code)
		}
	}
}

// ---- modo en vivo ---------------------------------------------------------------

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestLiveModeAlertsAsAttackHappens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte("Oct 12 08:00:00 srv sshd[1]: Failed password for root from 203.0.113.250 port 1 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out, errOut := &safeBuf{}, &safeBuf{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, append(base, "-f", path), strings.NewReader(""), out, errOut) }()
	time.Sleep(300 * time.Millisecond)

	// Empieza el ataque: 6 fallos nuevos (lo que ya estaba en el archivo se ignora sin -from-start).
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	for i := 0; i < 6; i++ {
		f.WriteString("Oct 12 08:01:0" + string(rune('0'+i)) + " srv sshd[1]: Failed password for root from 198.51.100.77 port 22 ssh2\n")
	}
	f.Close()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "NUEVA") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "NUEVA") || !strings.Contains(out.String(), "198.51.100.77") {
		t.Fatalf("no apareció la alerta en vivo:\n%s", out.String())
	}
	if strings.Contains(out.String(), "203.0.113.250") {
		t.Fatal("sin -from-start, lo anterior al arranque no debe analizarse")
	}

	cancel() // Ctrl+C
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("código %d, stderr: %s", code, errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no terminó tras cancelar")
	}
	if !strings.Contains(out.String(), "CENTINELA · informe") {
		t.Fatal("al terminar debe imprimir el resumen")
	}
}
