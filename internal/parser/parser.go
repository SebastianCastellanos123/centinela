// Package parser convierte líneas de log de sshd en eventos estructurados.
//
// Soporta los dos formatos más comunes:
//
//	syslog clásico:  Oct 12 04:27:30 servidor sshd[1234]: Failed password for root from 203.0.113.5 port 4242 ssh2
//	ISO (journalctl -o short-iso, rsyslog moderno):
//	                 2026-10-12T04:27:30-05:00 servidor sshd[1234]: Failed password for ...
package parser

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Kind string

const (
	KindFailed   Kind = "failed"   // intento de autenticación fallido
	KindAccepted Kind = "accepted" // acceso exitoso
)

// Event es un hecho relevante extraído de una línea del log.
type Event struct {
	Time        time.Time
	Host        string
	Kind        Kind
	Method      string // password, publickey, keyboard-interactive/pam...
	User        string
	IP          string
	Port        int
	InvalidUser bool // el usuario ni siquiera existe en el servidor
}

var (
	// "sshd-session" es el nombre del proceso en OpenSSH ≥ 9.8 (Debian 13, Ubuntu reciente).
	reSyslog = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (\S+) sshd(?:-session)?(?:\[\d+\])?: (.*)$`)
	reISO    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) sshd(?:-session)?(?:\[\d+\])?: (.*)$`)

	// IMPORTANTE (inyección de logs): el nombre de usuario lo escribe el atacante y
	// puede contener espacios. Por eso el usuario se captura con `(.+)` GREEDY y la
	// expresión está anclada al final de la línea: así "from IP port N" es siempre
	// el ÚLTIMO, el que añadió sshd, y no uno fabricado dentro del nombre de usuario.
	reFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.+) from (\S+) port (\d+)(?: ssh2)?(?:: .*)?$`)
	reAccepted = regexp.MustCompile(`^Accepted (\S+) for (.+) from (\S+) port (\d+)(?: ssh2)?(?:: .*)?$`)
)

var isoLayouts = []string{
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999-0700",
	"2006-01-02T15:04:05.999999999",
}

// Parser guarda el contexto necesario para interpretar fechas.
type Parser struct {
	// Year es el año de los logs en formato syslog (que no trae año). 0 = año actual.
	Year int
	// Loc es la zona horaria de los logs sin zona. nil = hora local del equipo.
	Loc *time.Location
	// Now se puede reemplazar en tests.
	Now func() time.Time
}

func New() *Parser { return &Parser{Now: time.Now, Loc: time.Local} }

// Parse devuelve el evento de una línea. ok=false si la línea no es un evento
// de autenticación SSH que nos interese (ruido, otro servicio, formato raro...).
func (p *Parser) Parse(line string) (ev Event, ok bool) {
	ts, host, msg, ok := p.splitHeader(line)
	if !ok {
		return Event{}, false
	}

	if m := reFailed.FindStringSubmatch(msg); m != nil {
		ip, port, valid := addr(m[4], m[5])
		if !valid {
			return Event{}, false
		}
		return Event{
			Time: ts, Host: host, Kind: KindFailed, Method: m[1],
			InvalidUser: m[2] != "", User: m[3], IP: ip, Port: port,
		}, true
	}
	if m := reAccepted.FindStringSubmatch(msg); m != nil {
		ip, port, valid := addr(m[3], m[4])
		if !valid {
			return Event{}, false
		}
		return Event{Time: ts, Host: host, Kind: KindAccepted, Method: m[1], User: m[2], IP: ip, Port: port}, true
	}
	return Event{}, false
}

func (p *Parser) splitHeader(line string) (time.Time, string, string, bool) {
	line = strings.TrimRight(line, "\r\n")
	if m := reISO.FindStringSubmatch(line); m != nil {
		t, ok := p.parseISO(m[1])
		return t, m[2], m[3], ok
	}
	if m := reSyslog.FindStringSubmatch(line); m != nil {
		t, ok := p.parseSyslog(m[1])
		return t, m[2], m[3], ok
	}
	return time.Time{}, "", "", false
}

func (p *Parser) parseISO(s string) (time.Time, bool) {
	s = strings.Replace(s, ",", ".", 1)
	for _, layout := range isoLayouts {
		if t, err := time.ParseInLocation(layout, s, p.loc()); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseSyslog: el formato clásico no trae año. Usamos Year (o el actual) y, si la
// fecha resultante queda en el futuro, asumimos que el log es del año anterior
// (típico al analizar en enero un log de diciembre).
func (p *Parser) parseSyslog(s string) (time.Time, bool) {
	t, err := time.ParseInLocation("Jan _2 15:04:05", s, p.loc())
	if err != nil {
		return time.Time{}, false
	}
	now := p.now()
	year := p.Year
	if year == 0 {
		year = now.Year()
	}
	t = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, p.loc())
	if p.Year == 0 && t.After(now.Add(24*time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

func (p *Parser) loc() *time.Location {
	if p.Loc != nil {
		return p.Loc
	}
	return time.Local
}

func (p *Parser) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// addr valida IP y puerto: una línea con una "IP" inválida se descarta, así el
// resto del programa solo maneja direcciones reales.
func addr(ipStr, portStr string) (string, int, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, false
	}
	return ip.String(), port, true // String() normaliza (IPv6 en minúsculas, etc.)
}
