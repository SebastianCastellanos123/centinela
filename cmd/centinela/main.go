// Centinela analiza logs de sshd y detecta fuerza bruta, rociado de contraseñas y
// accesos sospechosos. Solo LEE logs: nunca bloquea ni modifica nada.
package main

import (
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // zonas horarias embebidas (Windows no las trae)

	"github.com/SebastianCastellanos123/centinela/internal/detector"
	"github.com/SebastianCastellanos123/centinela/internal/follow"
	"github.com/SebastianCastellanos123/centinela/internal/parser"
	"github.com/SebastianCastellanos123/centinela/internal/report"
)

const usage = `Centinela: detector de ataques SSH en logs de Linux

Uso:
  centinela [opciones] archivo [archivo...]     (".gz" se descomprime solo)
  centinela [opciones] -                        (lee de la entrada estándar)
  journalctl -u ssh -o short-iso | centinela -

Las opciones van ANTES de los archivos. Si das varios archivos, pásalos del más
antiguo al más reciente (auth.log.2.gz auth.log.1 auth.log).

Opciones:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("centinela", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	var (
		format    = fs.String("format", "text", "formato del informe: text, json o markdown")
		window    = fs.Duration("window", 5*time.Minute, "ventana de tiempo para contar intentos")
		brute     = fs.Int("brute", 5, "fallos desde una IP para alertar de fuerza bruta")
		spray     = fs.Int("spray", 4, "usuarios distintos desde una IP para alertar de rociado")
		slow      = fs.Int("slow", 20, "fallos acumulados (sin límite de tiempo) para alertar de ataque lento; -1 lo desactiva")
		compro    = fs.Int("compromise", 3, "fallos previos para marcar un acceso exitoso como sospechoso")
		year      = fs.Int("year", 0, "año de los logs en formato syslog (0 = año actual)")
		tz        = fs.String("tz", "", "zona horaria de los logs sin zona, ej. America/Bogota (por defecto la del equipo)")
		live      = fs.Bool("f", false, "modo en vivo: sigue el archivo y avisa de alertas nuevas (como tail -f)")
		fromStart = fs.Bool("from-start", false, "con -f: analiza también lo que ya está en el archivo")
		failOn    = fs.String("fail-on", "none", "sale con código 2 si hay alertas de esta severidad o más: none, medium, high, critical")
	)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 1
	}

	if *format != "text" && *format != "json" && *format != "markdown" {
		fmt.Fprintf(stderr, "error: formato %q no válido (usa text, json o markdown)\n", *format)
		return 1
	}
	threshold, ok := parseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "error: -fail-on %q no válido (usa none, medium, high o critical)\n", *failOn)
		return 1
	}
	files := fs.Args()
	if len(files) == 0 {
		fs.Usage()
		return 1
	}

	p := parser.New()
	p.Year = *year
	if *tz != "" {
		loc, err := time.LoadLocation(*tz)
		if err != nil {
			fmt.Fprintf(stderr, "error: zona horaria %q desconocida\n", *tz)
			return 1
		}
		p.Loc = loc
	}
	det := detector.New(detector.Config{
		Window: *window, BruteForceFailures: *brute, SprayUsers: *spray, CompromiseFailures: *compro, SlowFailures: *slow,
	})

	res := report.Result{}
	var outOfOrder int
	var prev time.Time
	feed := func(line string) {
		res.Lines++
		ev, ok := p.Parse(line)
		if !ok {
			res.Ignored++
			return
		}
		if !prev.IsZero() && ev.Time.Before(prev.Add(-time.Minute)) {
			outOfOrder++
		}
		if ev.Time.After(prev) {
			prev = ev.Time
		}
		det.Process(ev)
	}

	if *live {
		if len(files) != 1 || files[0] == "-" || strings.HasSuffix(files[0], ".gz") {
			fmt.Fprintln(stderr, "error: -f necesita exactamente un archivo de texto (no stdin ni .gz)")
			return 1
		}
		det.OnAlert = func(a *detector.Alert, escalated bool) { liveAlert(stdout, a, escalated) }
		fmt.Fprintf(stderr, "Vigilando %s (Ctrl+C para terminar y ver el resumen)...\n", files[0])

		lines := make(chan string, 256)
		errc := make(chan error, 1)
		go func() { errc <- follow.Lines(ctx, files[0], *fromStart, 500*time.Millisecond, lines) }()
	loop:
		for {
			select {
			case line := <-lines:
				feed(line)
			case err := <-errc:
				if err != nil {
					fmt.Fprintf(stderr, "error: %v\n", err)
					return 1
				}
				break loop
			}
		}
		fmt.Fprintln(stdout)
	} else {
		for _, name := range files {
			if err := readFile(name, stdin, feed); err != nil {
				fmt.Fprintf(stderr, "error leyendo %s: %v\n", name, err)
				return 1
			}
		}
	}

	res.Stats = det.Stats()
	res.Alerts = det.Alerts()

	switch *format {
	case "json":
		if err := report.JSON(stdout, res); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	case "markdown":
		report.Markdown(stdout, res)
	default:
		report.Text(stdout, res)
	}

	if outOfOrder > 0 {
		fmt.Fprintf(stderr, "\naviso: %d eventos estaban fuera de orden cronológico. Pasa los archivos del más antiguo al más reciente o los conteos pueden ser imprecisos.\n", outOfOrder)
	}
	if threshold >= 0 {
		for _, a := range res.Alerts {
			if a.Severity >= threshold {
				return 2
			}
		}
	}
	return 0
}

func readFile(name string, stdin io.Reader, fn func(string)) error {
	if name == "-" {
		return follow.ForEachLine(stdin, fn)
	}
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(name, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	return follow.ForEachLine(r, fn)
}

// parseSeverity: devuelve -1 para "none".
func parseSeverity(s string) (detector.Severity, bool) {
	switch strings.ToLower(s) {
	case "none":
		return -1, true
	case "medium":
		return detector.Medium, true
	case "high":
		return detector.High, true
	case "critical":
		return detector.Critical, true
	}
	return 0, false
}

func liveAlert(w io.Writer, a *detector.Alert, escalated bool) {
	verb := "NUEVA"
	if escalated {
		verb = "SUBE"
	}
	extra := fmt.Sprintf("%d intentos", a.Attempts)
	if a.Rule == detector.RuleCompromise {
		extra = fmt.Sprintf("entró como %q por %s tras %d fallos", report.Sanitize(a.Targeted), a.Method, a.Attempts)
	}
	fmt.Fprintf(w, "[%s] %s %-8s %-22s %-39s %s\n",
		a.LastSeen.Format("15:04:05"), verb, strings.ToUpper(a.Severity.String()), a.Rule, a.IP, extra)
}
