package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SebastianCastellanos123/centinela/internal/detector"
)

func TestSanitizeNeutralizesControlCharsAndLength(t *testing.T) {
	got := Sanitize("\x1b[2J\x1b[31mroot\x1b[0m\r\n\x00")
	if strings.ContainsAny(got, "\x1b\r\n\x00") {
		t.Fatalf("quedaron caracteres de control: %q", got)
	}
	long := Sanitize(strings.Repeat("a", 500))
	if n := len([]rune(long)); n > 41 {
		t.Fatalf("debe recortarse: %d runas", n)
	}
	if Sanitize("ana.pérez") != "ana.pérez" {
		t.Fatal("el texto normal (con tildes) no debe alterarse")
	}
}

func sampleResult() Result {
	t0 := time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)
	return Result{
		Lines: 10, Ignored: 2,
		Stats: detector.Stats{Events: 8, Failed: 7, Accepted: 1, UniqueIPs: 2, First: t0, Last: t0.Add(time.Minute),
			TopIPs: map[string]int{"203.0.113.9": 7}, TopUsers: map[string]int{"evil|`user`<b>": 7}},
		Alerts: []*detector.Alert{{
			Rule: detector.RuleBruteForce, Severity: detector.High, IP: "203.0.113.9",
			FirstSeen: t0, LastSeen: t0.Add(time.Minute), Attempts: 7,
			Users: map[string]int{"evil|`user`<b>\x1b[31m": 7},
		}},
	}
}

func TestTextHasNoEscapeSequences(t *testing.T) {
	var b bytes.Buffer
	Text(&b, sampleResult())
	if strings.Contains(b.String(), "\x1b") {
		t.Fatalf("el informe no debe contener secuencias de escape del atacante:\n%q", b.String())
	}
	if !strings.Contains(b.String(), "ALTA") || !strings.Contains(b.String(), "203.0.113.9") {
		t.Fatalf("falta contenido esperado:\n%s", b.String())
	}
}

func TestTextNoAlerts(t *testing.T) {
	var b bytes.Buffer
	Text(&b, Result{Lines: 3})
	if !strings.Contains(b.String(), "Sin alertas") {
		t.Fatal(b.String())
	}
}

func TestMarkdownEscapesAttackerText(t *testing.T) {
	var b bytes.Buffer
	Markdown(&b, sampleResult())
	out := b.String()
	for _, row := range strings.Split(out, "\n") {
		if strings.HasPrefix(row, "| alta") {
			// Una fila válida de la tabla tiene exactamente 7 columnas (8 barras sin escapar).
			if n := strings.Count(strings.ReplaceAll(row, `\|`, ""), "|"); n != 8 {
				t.Fatalf("el usuario del atacante rompió la tabla (%d barras): %s", n, row)
			}
		}
	}
	if strings.Contains(out, "<b>") || strings.Contains(out, "\x1b") {
		t.Fatalf("HTML o escapes sin neutralizar:\n%q", out)
	}
}

func TestJSONIsValidAndSanitized(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}
	alerts := got["alerts"].([]any)
	if len(alerts) != 1 || alerts[0].(map[string]any)["severity"] != "high" {
		t.Fatalf("alertas: %v", alerts)
	}
	// Sin alertas, "alerts" debe ser [] y no null.
	b.Reset()
	_ = JSON(&b, Result{})
	if !strings.Contains(b.String(), `"alerts": []`) {
		t.Fatalf("esperaba lista vacía: %s", b.String())
	}
}

func TestRecommendationsDoNotBlockInternalIPs(t *testing.T) {
	r := []*detector.Alert{{Rule: detector.RuleBruteForce, Severity: detector.High, IP: "10.0.0.7", Users: map[string]int{}}}
	rec := strings.Join(recommendations(r), "\n")
	if strings.Contains(rec, "ufw deny from 10.0.0.7") || !strings.Contains(rec, "IP interna") {
		t.Fatalf("no debe sugerir bloquear una IP interna: %s", rec)
	}
	if len(recommendations(nil)) != 0 {
		t.Fatal("sin alertas no hay recomendaciones")
	}
}
