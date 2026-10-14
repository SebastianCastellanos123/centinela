package follow

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestForEachLineHandlesLongAndLastLine(t *testing.T) {
	long := strings.Repeat("a", 200_000)
	input := "uno\r\n" + long + "\ndos\nsin-salto-final"
	var got []string
	if err := ForEachLine(strings.NewReader(input), func(s string) { got = append(got, s) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0] != "uno" || got[2] != "dos" || got[3] != "sin-salto-final" {
		t.Fatalf("líneas: %d %q", len(got), got)
	}
	if len(got[1]) > MaxLine {
		t.Fatalf("la línea larga debe recortarse: %d", len(got[1]))
	}
}

func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("se agotó el tiempo esperando una línea")
		return ""
	}
}

func start(t *testing.T, path string, fromStart bool) (<-chan string, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan string, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Lines(ctx, path, fromStart, 10*time.Millisecond, ch)
	}()
	// Esperar a que la goroutine cierre el archivo ANTES de que se borre el directorio
	// temporal (en Windows no se puede borrar un archivo abierto).
	t.Cleanup(func() { cancel(); <-done })
	return ch, cancel
}

func appendTo(t *testing.T, path, s string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestFollowOnlyNewLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "vieja 1\nvieja 2\n")

	ch, cancel := start(t, path, false)
	defer cancel()
	time.Sleep(50 * time.Millisecond)
	appendTo(t, path, "nueva 1\nnueva 2\n")

	if got := recv(t, ch); got != "nueva 1" {
		t.Fatalf("got %q", got)
	}
	if got := recv(t, ch); got != "nueva 2" {
		t.Fatalf("got %q", got)
	}
}

func TestFollowFromStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "a\nb\n")
	ch, cancel := start(t, path, true)
	defer cancel()
	if recv(t, ch) != "a" || recv(t, ch) != "b" {
		t.Fatal("debía leer desde el inicio")
	}
}

func TestFollowJoinsPartialLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "")
	ch, cancel := start(t, path, true)
	defer cancel()

	appendTo(t, path, "mitad de una ")
	time.Sleep(60 * time.Millisecond)
	appendTo(t, path, "línea\n")
	if got := recv(t, ch); got != "mitad de una línea" {
		t.Fatalf("una línea a medio escribir debe esperar a completarse: %q", got)
	}
}

func TestFollowSurvivesRotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("en Windows no se puede renombrar un archivo que está abierto; logrotate es propio de Linux")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	appendTo(t, path, "antes\n")
	ch, cancel := start(t, path, true)
	defer cancel()
	if recv(t, ch) != "antes" {
		t.Fatal("primera línea")
	}

	// logrotate: renombra el archivo y crea uno nuevo.
	if err := os.Rename(path, filepath.Join(dir, "auth.log.1")); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, "despues-de-rotar\n")
	if got := recv(t, ch); got != "despues-de-rotar" {
		t.Fatalf("tras rotar debe leer el archivo nuevo: %q", got)
	}
}

func TestFollowSurvivesTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	appendTo(t, path, "una linea larga larga larga\n")
	ch, cancel := start(t, path, true)
	defer cancel()
	recv(t, ch)

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	appendTo(t, path, "tras truncar\n")
	if got := recv(t, ch); got != "tras truncar" {
		t.Fatalf("got %q", got)
	}
}

func TestFollowMissingFile(t *testing.T) {
	err := Lines(context.Background(), filepath.Join(t.TempDir(), "no-existe.log"), false, time.Millisecond, make(chan string))
	if err == nil {
		t.Fatal("un archivo inexistente debe dar error")
	}
}
