// Package report da formato a los resultados del detector (texto, JSON, Markdown).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/SebastianCastellanos123/centinela/internal/detector"
)

// Result agrupa todo lo necesario para generar un informe.
type Result struct {
	Lines   int // líneas leídas
	Ignored int // líneas que no eran eventos SSH de autenticación
	Stats   detector.Stats
	Alerts  []*detector.Alert
}

// Sanitize limpia texto que viene del log antes de mostrarlo. Los nombres de usuario
// los controla el atacante: podrían incluir secuencias de escape de terminal (para
// ocultar o falsificar líneas del informe) o ser enormes. Aquí se neutralizan.
func Sanitize(s string) string {
	const maxLen = 40
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxLen {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

var ruleTitles = map[string]string{
	detector.RuleCompromise: "Acceso exitoso tras fallos (posible compromiso)",
	detector.RuleBruteForce: "Fuerza bruta",
	detector.RuleSpraying:   "Rociado de contraseñas (muchos usuarios)",
	detector.RuleSlow:       "Ataque lento (intentos espaciados en el tiempo)",
}

func title(rule string) string {
	if t, ok := ruleTitles[rule]; ok {
		return t
	}
	return rule
}

// topUsers devuelve los n usuarios más atacados de una alerta.
func topUsers(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	out := []string{}
	for i, e := range list {
		if i == n {
			out = append(out, fmt.Sprintf("… y %d más", len(list)-n))
			break
		}
		out = append(out, fmt.Sprintf("%s (%d)", Sanitize(e.k), e.v))
	}
	return out
}

func topN(m map[string]int, n int) [][2]string {
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	if len(list) > n {
		list = list[:n]
	}
	out := make([][2]string, len(list))
	for i, e := range list {
		out[i] = [2]string{Sanitize(e.k), fmt.Sprint(e.v)}
	}
	return out
}

func isInternal(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast())
}

func ts(t time.Time) string { return t.Format("2006-01-02 15:04:05") }

func dur(a *detector.Alert) string {
	d := a.LastSeen.Sub(a.FirstSeen).Round(time.Second)
	if d <= 0 {
		return "instantáneo"
	}
	return d.String()
}

// recommendations devuelve acciones sugeridas. Centinela NUNCA ejecuta nada: solo sugiere.
func recommendations(alerts []*detector.Alert) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range alerts {
		if a.Rule == detector.RuleCompromise {
			out = append(out, fmt.Sprintf("REVISA YA la cuenta %q: cambia su contraseña, revisa ~/.ssh/authorized_keys, `last -a` y el historial de comandos. La IP %s entró después de %d fallos.", Sanitize(a.Targeted), a.IP, a.Attempts))
		}
	}
	for _, a := range alerts {
		if a.Severity < detector.High || seen[a.IP] {
			continue
		}
		seen[a.IP] = true
		if isInternal(a.IP) {
			out = append(out, fmt.Sprintf("%s es una IP interna: investiga el equipo antes de bloquear.", a.IP))
			continue
		}
		out = append(out, fmt.Sprintf("Bloquear %s:  sudo ufw deny from %s   (o: sudo iptables -I INPUT -s %s -j DROP)", a.IP, a.IP, a.IP))
	}
	if len(out) > 0 {
		out = append(out, "Mejoras generales: desactiva el acceso por contraseña (PasswordAuthentication no), prohíbe root (PermitRootLogin no) e instala fail2ban.")
	}
	return out
}

// ---- texto ------------------------------------------------------------------

func Text(w io.Writer, r Result) {
	s := r.Stats
	fmt.Fprintln(w, "CENTINELA · informe de accesos SSH")
	fmt.Fprintln(w, strings.Repeat("=", 60))
	if s.Events > 0 {
		fmt.Fprintf(w, "Período:        %s → %s\n", ts(s.First), ts(s.Last))
	}
	fmt.Fprintf(w, "Líneas leídas:  %d (eventos SSH: %d, ignoradas: %d)\n", r.Lines, s.Events, r.Ignored)
	fmt.Fprintf(w, "Fallos:         %d   Accesos exitosos: %d   IPs distintas: %d\n", s.Failed, s.Accepted, s.UniqueIPs)
	fmt.Fprintln(w)

	if len(r.Alerts) == 0 {
		fmt.Fprintln(w, "Sin alertas. No se detectó actividad sospechosa con los umbrales actuales.")
	} else {
		fmt.Fprintf(w, "ALERTAS (%d)\n\n", len(r.Alerts))
		for _, a := range r.Alerts {
			tag := strings.ToUpper(a.Severity.String())
			fmt.Fprintf(w, "[%s] %s\n", tag, title(a.Rule))
			fmt.Fprintf(w, "   IP: %s%s\n", a.IP, internalNote(a.IP))
			fmt.Fprintf(w, "   Cuándo: %s → %s (%s)\n", ts(a.FirstSeen), ts(a.LastSeen), dur(a))
			if a.Rule == detector.RuleCompromise {
				fmt.Fprintf(w, "   Entró como %q por %s tras %d fallos recientes\n", Sanitize(a.Targeted), a.Method, a.Attempts)
			} else {
				fmt.Fprintf(w, "   Intentos: %d", a.Attempts)
				if a.InvalidFr > 0 {
					fmt.Fprintf(w, " (%d contra usuarios que no existen)", a.InvalidFr)
				}
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "   Usuarios probados: %s\n\n", strings.Join(topUsers(a.Users, 5), ", "))
		}
	}

	if top := topN(s.TopIPs, 5); len(top) > 0 {
		fmt.Fprintln(w, "IPs con más fallos")
		for _, e := range top {
			fmt.Fprintf(w, "   %-40s %s\n", e[0], e[1])
		}
		fmt.Fprintln(w)
	}
	if top := topN(s.TopUsers, 5); len(top) > 0 {
		fmt.Fprintln(w, "Usuarios más atacados")
		for _, e := range top {
			fmt.Fprintf(w, "   %-40s %s\n", e[0], e[1])
		}
		fmt.Fprintln(w)
	}
	if rec := recommendations(r.Alerts); len(rec) > 0 {
		fmt.Fprintln(w, "ACCIONES SUGERIDAS (Centinela no ejecuta nada por ti)")
		for _, line := range rec {
			fmt.Fprintf(w, " - %s\n", line)
		}
	}
}

func internalNote(ip string) string {
	if isInternal(ip) {
		return "  (red interna)"
	}
	return ""
}

// ---- JSON ---------------------------------------------------------------------

type jsonAlert struct {
	Rule      string         `json:"rule"`
	Severity  string         `json:"severity"`
	IP        string         `json:"ip"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Attempts  int            `json:"attempts"`
	Targeted  string         `json:"targeted_account,omitempty"`
	Method    string         `json:"method,omitempty"`
	Users     map[string]int `json:"users"`
}

type jsonReport struct {
	Lines     int         `json:"lines"`
	Ignored   int         `json:"ignored"`
	Events    int         `json:"events"`
	Failed    int         `json:"failed"`
	Accepted  int         `json:"accepted"`
	UniqueIPs int         `json:"unique_ips"`
	First     *time.Time  `json:"first,omitempty"`
	Last      *time.Time  `json:"last,omitempty"`
	Alerts    []jsonAlert `json:"alerts"`
}

func JSON(w io.Writer, r Result) error {
	out := jsonReport{
		Lines: r.Lines, Ignored: r.Ignored, Events: r.Stats.Events, Failed: r.Stats.Failed,
		Accepted: r.Stats.Accepted, UniqueIPs: r.Stats.UniqueIPs, Alerts: []jsonAlert{},
	}
	if r.Stats.Events > 0 {
		f, l := r.Stats.First, r.Stats.Last
		out.First, out.Last = &f, &l
	}
	sevName := map[detector.Severity]string{detector.Low: "low", detector.Medium: "medium", detector.High: "high", detector.Critical: "critical"}
	for _, a := range r.Alerts {
		users := map[string]int{}
		for u, n := range a.Users { // json.Encoder ya escapa los caracteres de control
			users[Sanitize(u)] += n
		}
		out.Alerts = append(out.Alerts, jsonAlert{
			Rule: a.Rule, Severity: sevName[a.Severity], IP: a.IP, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen,
			Attempts: a.Attempts, Targeted: Sanitize(a.Targeted), Method: a.Method, Users: users,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ---- Markdown -------------------------------------------------------------------

func mdEscape(s string) string {
	r := strings.NewReplacer("|", "\\|", "`", "'", "<", "&lt;", ">", "&gt;", "\n", " ")
	return r.Replace(Sanitize(s))
}

// mdText escapa texto largo (sin truncar). Los textos que vienen del atacante deben
// pasar antes por Sanitize.
func mdText(s string) string {
	return strings.NewReplacer("|", "\\|", "<", "&lt;", ">", "&gt;", "\n", " ").Replace(s)
}

func Markdown(w io.Writer, r Result) {
	s := r.Stats
	fmt.Fprintln(w, "# Informe de accesos SSH")
	fmt.Fprintln(w)
	if s.Events > 0 {
		fmt.Fprintf(w, "**Período:** %s → %s\n\n", ts(s.First), ts(s.Last))
	}
	fmt.Fprintf(w, "| Líneas | Eventos SSH | Fallos | Accesos exitosos | IPs distintas |\n|---:|---:|---:|---:|---:|\n| %d | %d | %d | %d | %d |\n\n",
		r.Lines, s.Events, s.Failed, s.Accepted, s.UniqueIPs)

	if len(r.Alerts) == 0 {
		fmt.Fprintln(w, "Sin alertas.")
		return
	}
	fmt.Fprintf(w, "## Alertas (%d)\n\n| Severidad | Regla | IP | Inicio | Duración | Intentos | Usuarios probados |\n|---|---|---|---|---|---:|---|\n", len(r.Alerts))
	for _, a := range r.Alerts {
		users := make([]string, 0)
		for _, u := range topUsers(a.Users, 3) {
			users = append(users, mdEscape(u))
		}
		fmt.Fprintf(w, "| %s | %s | `%s` | %s | %s | %d | %s |\n",
			a.Severity, title(a.Rule), a.IP, ts(a.FirstSeen), dur(a), a.Attempts, strings.Join(users, ", "))
	}
	if rec := recommendations(r.Alerts); len(rec) > 0 {
		fmt.Fprint(w, "\n## Acciones sugeridas\n\n")
		for _, line := range rec {
			fmt.Fprintf(w, "- %s\n", mdText(line))
		}
	}
}
