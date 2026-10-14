// Package detector analiza eventos SSH y genera alertas.
//
// Reglas:
//
//	brute_force            ≥ N fallos desde una misma IP dentro de una ventana de tiempo.
//	password_spraying      ≥ M usuarios DISTINTOS probados desde una misma IP en la ventana
//	                       (el atacante prueba pocas claves contra muchas cuentas).
//	slow_scan              ≥ S fallos acumulados desde una IP SIN importar el tiempo. Cubre
//	                       los ataques "lentos" que esquivan las reglas con ventana
//	                       (un intento cada pocos minutos).
//	success_after_failures un acceso EXITOSO desde una IP que venía fallando: posible
//	                       compromiso. Es la alerta más importante.
//
// Los eventos deben llegar en orden cronológico (como están en un log).
package detector

import (
	"sort"
	"time"

	"github.com/SebastianCastellanos123/centinela/internal/parser"
)

type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Medium:
		return "media"
	case High:
		return "alta"
	case Critical:
		return "crítica"
	default:
		return "baja"
	}
}

// Nombres de las reglas.
const (
	RuleBruteForce = "brute_force"
	RuleSpraying   = "password_spraying"
	RuleCompromise = "success_after_failures"
	RuleSlow       = "slow_scan"
)

type Config struct {
	Window             time.Duration // ventana deslizante (por defecto 5 min)
	BruteForceFailures int           // fallos para alertar de fuerza bruta (5)
	SprayUsers         int           // usuarios distintos para alertar de rociado (4)
	CompromiseFailures int           // fallos previos para marcar un acceso sospechoso (3)
	SlowFailures       int           // fallos acumulados para alertar de ataque lento (20); -1 lo desactiva
}

func DefaultConfig() Config {
	return Config{Window: 5 * time.Minute, BruteForceFailures: 5, SprayUsers: 4, CompromiseFailures: 3, SlowFailures: 20}
}

// Límites de memoria: el atacante controla cuántos usuarios e IPs distintos aparecen
// en el log, así que ninguna estructura puede crecer sin tope.
const (
	maxUsersPerAlert = 100
	maxGlobalKeys    = 50_000
	gcEvery          = 5_000 // cada cuántos eventos se limpian IPs inactivas
)

// Alert es un hallazgo: una IP que cumplió una regla durante un "episodio".
type Alert struct {
	Rule      string
	Severity  Severity
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
	Attempts  int            // fallos acumulados en el episodio
	Users     map[string]int // usuarios atacados → número de intentos
	Targeted  string         // en success_after_failures: la cuenta a la que se entró
	Method    string         // método con el que se entró (password, publickey...)
	InvalidFr int            // cuántos intentos fueron contra usuarios que no existen
}

type Stats struct {
	Events    int
	Failed    int
	Accepted  int
	First     time.Time
	Last      time.Time
	UniqueIPs int
	TopIPs    map[string]int // fallos por IP
	TopUsers  map[string]int // fallos por usuario
	ipsSeen   map[string]struct{}
}

type failure struct {
	t       time.Time
	user    string
	invalid bool
}

// maxFailsPerIP limita cuántos fallos recordamos por IP. Si un atacante manda
// millones de intentos, olvidamos los más viejos en lugar de agotar la memoria.
const maxFailsPerIP = 10_000

// ipState guarda los fallos recientes de una IP. Mantiene un contador de usuarios
// distintos de forma INCREMENTAL: añadir o descartar un fallo cuesta O(1), así el
// análisis no se vuelve lento aunque el atacante mande cientos de miles de intentos.
type ipState struct {
	fails []failure // los vigentes son fails[head:]
	head  int
	users map[string]int // usuario → fallos vigentes con ese usuario
	last  time.Time
}

func (s *ipState) count() int { return len(s.fails) - s.head }

func (s *ipState) window() []failure { return s.fails[s.head:] }

func (s *ipState) add(f failure) {
	s.fails = append(s.fails, f)
	if s.users == nil {
		s.users = make(map[string]int)
	}
	s.users[f.user]++
	for s.count() > maxFailsPerIP {
		s.drop()
	}
}

func (s *ipState) drop() {
	f := s.fails[s.head]
	if s.users[f.user]--; s.users[f.user] <= 0 {
		delete(s.users, f.user)
	}
	s.head++
	// Compacta de vez en cuando para no retener memoria de elementos ya descartados.
	if s.head > 1024 && s.head > len(s.fails)/2 {
		s.fails = append(s.fails[:0], s.fails[s.head:]...)
		s.head = 0
	}
}

type Detector struct {
	cfg    Config
	ips    map[string]*ipState
	active map[string]*Alert // clave "regla|ip" → episodio abierto

	// Seguimiento de largo plazo por IP (ataques lentos). Acotado a maxGlobalKeys.
	slowTrack     map[string]*Alert
	windowAlerted map[string]bool // IPs que ya tienen una alerta de fuerza bruta o rociado
	alerts        []*Alert
	stats         Stats
	n             int

	// OnAlert se llama cuando nace una alerta y cuando sube de severidad
	// (útil para el modo en vivo).
	OnAlert func(a *Alert, escalated bool)
}

func New(cfg Config) *Detector {
	def := DefaultConfig()
	if cfg.Window <= 0 {
		cfg.Window = def.Window
	}
	if cfg.BruteForceFailures <= 0 {
		cfg.BruteForceFailures = def.BruteForceFailures
	}
	if cfg.SprayUsers <= 0 {
		cfg.SprayUsers = def.SprayUsers
	}
	if cfg.CompromiseFailures <= 0 {
		cfg.CompromiseFailures = def.CompromiseFailures
	}
	if cfg.SlowFailures == 0 {
		cfg.SlowFailures = def.SlowFailures
	}
	return &Detector{
		cfg:           cfg,
		slowTrack:     make(map[string]*Alert),
		windowAlerted: make(map[string]bool),
		ips:           make(map[string]*ipState),
		active:        make(map[string]*Alert),
		stats: Stats{
			TopIPs:   make(map[string]int),
			TopUsers: make(map[string]int),
			ipsSeen:  make(map[string]struct{}),
		},
	}
}

// Process analiza un evento.
func (d *Detector) Process(ev parser.Event) {
	d.n++
	d.stats.Events++
	if d.stats.First.IsZero() || ev.Time.Before(d.stats.First) {
		d.stats.First = ev.Time
	}
	if ev.Time.After(d.stats.Last) {
		d.stats.Last = ev.Time
	}
	if len(d.stats.ipsSeen) < maxGlobalKeys {
		d.stats.ipsSeen[ev.IP] = struct{}{}
		d.stats.UniqueIPs = len(d.stats.ipsSeen)
	}

	st := d.state(ev.IP)
	st.last = ev.Time
	d.prune(st, ev.Time)

	switch ev.Kind {
	case parser.KindFailed:
		d.stats.Failed++
		bump(d.stats.TopIPs, ev.IP)
		bump(d.stats.TopUsers, ev.User)
		st.add(failure{t: ev.Time, user: ev.User, invalid: ev.InvalidUser})
		d.checkBruteForce(ev, st)
		d.checkSpraying(ev, st)
		d.checkSlow(ev)

	case parser.KindAccepted:
		d.stats.Accepted++
		d.checkCompromise(ev, st)
	}

	if d.n%gcEvery == 0 {
		d.gc(ev.Time)
	}
}

// Alerts devuelve todas las alertas, de más grave a menos grave.
func (d *Detector) Alerts() []*Alert {
	out := make([]*Alert, len(d.alerts))
	copy(out, d.alerts)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Attempts != out[j].Attempts {
			return out[i].Attempts > out[j].Attempts
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}

func (d *Detector) Stats() Stats { return d.stats }

// ---- reglas ----------------------------------------------------------------

func (d *Detector) checkBruteForce(ev parser.Event, st *ipState) {
	n := st.count()
	if n < d.cfg.BruteForceFailures {
		return
	}
	a, isNew := d.episode(RuleBruteForce, ev.IP, ev.Time)
	if isNew {
		// Al nacer, cuenta los fallos que ya había dentro de la ventana.
		a.Attempts = n
		for _, f := range st.window() {
			d.addUser(a, f)
		}
	} else {
		a.Attempts++
		d.addUser(a, st.fails[len(st.fails)-1])
	}
	sev := Medium
	if a.Attempts >= 4*d.cfg.BruteForceFailures {
		sev = High
	}
	d.notify(a, sev, isNew)
}

func (d *Detector) checkSpraying(ev parser.Event, st *ipState) {
	if len(st.users) < d.cfg.SprayUsers { // usuarios distintos vigentes: O(1)
		return
	}
	a, isNew := d.episode(RuleSpraying, ev.IP, ev.Time)
	if isNew {
		a.Attempts = st.count()
		for _, f := range st.window() {
			d.addUser(a, f)
		}
	} else {
		a.Attempts++
		d.addUser(a, st.fails[len(st.fails)-1])
	}
	sev := Medium
	if len(a.Users) >= 3*d.cfg.SprayUsers {
		sev = High
	}
	d.notify(a, sev, isNew)
}

func (d *Detector) checkCompromise(ev parser.Event, st *ipState) {
	if st.count() < d.cfg.CompromiseFailures {
		return
	}
	a, isNew := d.episode(RuleCompromise, ev.IP, ev.Time)
	if !isNew {
		return
	}
	a.Attempts = st.count()
	a.Targeted = ev.User
	a.Method = ev.Method
	for _, f := range st.window() {
		d.addUser(a, f)
	}
	d.notify(a, Critical, true)
}

// checkSlow detecta ataques lentos: acumula TODOS los fallos de una IP durante todo
// el análisis. Si la IP ya tiene una alerta de fuerza bruta o rociado no se duplica
// el aviso (esa alerta ya cubre el caso).
func (d *Detector) checkSlow(ev parser.Event) {
	if d.cfg.SlowFailures < 0 {
		return
	}
	tr, ok := d.slowTrack[ev.IP]
	if !ok {
		if len(d.slowTrack) >= maxGlobalKeys {
			return
		}
		tr = &Alert{Rule: RuleSlow, IP: ev.IP, FirstSeen: ev.Time, Users: map[string]int{}}
		d.slowTrack[ev.IP] = tr
	}
	tr.LastSeen = ev.Time
	tr.Attempts++
	d.addUser(tr, failure{user: ev.User, invalid: ev.InvalidUser})

	if tr.Attempts < d.cfg.SlowFailures || d.windowAlerted[ev.IP] {
		return
	}
	if !d.slowPublished(tr) {
		d.alerts = append(d.alerts, tr)
		d.notify(tr, Medium, true)
	}
}

func (d *Detector) slowPublished(a *Alert) bool { return a.Severity != Low }

// ---- utilidades -------------------------------------------------------------

// episode devuelve el episodio abierto para (regla, IP) o crea uno nuevo.
// Un episodio sigue "abierto" mientras la IP no pase más de una ventana en silencio;
// así un ataque de 3 horas es UNA alerta con sus totales, no 500 alertas.
func (d *Detector) episode(rule, ip string, t time.Time) (*Alert, bool) {
	key := rule + "|" + ip
	if a, ok := d.active[key]; ok && t.Sub(a.LastSeen) <= d.cfg.Window {
		a.LastSeen = t
		return a, false
	}
	a := &Alert{Rule: rule, IP: ip, FirstSeen: t, LastSeen: t, Users: map[string]int{}}
	if rule == RuleBruteForce || rule == RuleSpraying {
		d.windowAlerted[ip] = true
	}
	d.active[key] = a
	d.alerts = append(d.alerts, a)
	return a, true
}

func (d *Detector) notify(a *Alert, sev Severity, isNew bool) {
	escalated := sev > a.Severity
	if sev > a.Severity {
		a.Severity = sev
	}
	if d.OnAlert != nil && (isNew || escalated) {
		d.OnAlert(a, !isNew && escalated)
	}
}

func (d *Detector) addUser(a *Alert, f failure) {
	if _, exists := a.Users[f.user]; exists || len(a.Users) < maxUsersPerAlert {
		a.Users[f.user]++
	}
	if f.invalid {
		a.InvalidFr++
	}
}

func (d *Detector) state(ip string) *ipState {
	st, ok := d.ips[ip]
	if !ok {
		st = &ipState{}
		d.ips[ip] = st
	}
	return st
}

// prune descarta los fallos que quedaron fuera de la ventana.
func (d *Detector) prune(st *ipState, now time.Time) {
	for st.count() > 0 && now.Sub(st.fails[st.head].t) > d.cfg.Window {
		st.drop()
	}
}

// gc borra el estado de IPs que llevan más de una ventana sin actividad.
func (d *Detector) gc(now time.Time) {
	for ip, st := range d.ips {
		if now.Sub(st.last) > d.cfg.Window {
			delete(d.ips, ip)
		}
	}
	for k, a := range d.active {
		if now.Sub(a.LastSeen) > d.cfg.Window {
			delete(d.active, k)
		}
	}
}

func bump(m map[string]int, key string) {
	if _, ok := m[key]; ok || len(m) < maxGlobalKeys {
		m[key]++
	}
}
