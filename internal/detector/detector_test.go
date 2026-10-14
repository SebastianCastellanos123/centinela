package detector

import (
	"fmt"
	"testing"
	"time"

	"github.com/SebastianCastellanos123/centinela/internal/parser"
)

var t0 = time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC)

func fail(ip, user string, at time.Duration) parser.Event {
	return parser.Event{Time: t0.Add(at), Kind: parser.KindFailed, User: user, IP: ip, Method: "password"}
}

func ok(ip, user string, at time.Duration) parser.Event {
	return parser.Event{Time: t0.Add(at), Kind: parser.KindAccepted, User: user, IP: ip, Method: "password"}
}

func feed(d *Detector, evs ...parser.Event) {
	for _, e := range evs {
		d.Process(e)
	}
}

func rules(d *Detector) map[string]*Alert {
	m := map[string]*Alert{}
	for _, a := range d.Alerts() {
		m[a.Rule+"|"+a.IP] = a
	}
	return m
}

func TestNoAlertBelowThreshold(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 4; i++ { // el umbral es 5
		d.Process(fail("203.0.113.1", "root", time.Duration(i)*time.Second))
	}
	if n := len(d.Alerts()); n != 0 {
		t.Fatalf("no esperaba alertas, hay %d", n)
	}
}

func TestBruteForceAtThreshold(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 5; i++ {
		d.Process(fail("203.0.113.1", "root", time.Duration(i)*time.Second))
	}
	a := rules(d)[RuleBruteForce+"|203.0.113.1"]
	if a == nil || a.Severity != Medium || a.Attempts != 5 || a.Users["root"] != 5 {
		t.Fatalf("alerta inesperada: %+v", a)
	}
}

func TestBruteForceEscalatesAndMergesIntoOneEpisode(t *testing.T) {
	d := New(DefaultConfig())
	var events []string
	d.OnAlert = func(a *Alert, escalated bool) { events = append(events, fmt.Sprintf("%s/%v", a.Severity, escalated)) }

	for i := 0; i < 60; i++ {
		d.Process(fail("203.0.113.1", "root", time.Duration(i)*time.Second))
	}
	all := d.Alerts()
	if len(all) != 1 {
		t.Fatalf("un ataque continuo debe ser UNA alerta, hay %d", len(all))
	}
	a := all[0]
	if a.Severity != High || a.Attempts != 60 {
		t.Fatalf("esperaba alta con 60 intentos: %+v", a)
	}
	// Solo se notifica el nacimiento y la subida de severidad, no cada fallo.
	if len(events) != 2 || events[0] != "media/false" || events[1] != "alta/true" {
		t.Fatalf("notificaciones: %v", events)
	}
}

func TestNewEpisodeAfterQuietPeriod(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 6; i++ {
		d.Process(fail("203.0.113.1", "root", time.Duration(i)*time.Second))
	}
	// 1 hora de silencio y vuelve a atacar.
	for i := 0; i < 6; i++ {
		d.Process(fail("203.0.113.1", "root", time.Hour+time.Duration(i)*time.Second))
	}
	if n := len(d.Alerts()); n != 2 {
		t.Fatalf("esperaba 2 episodios, hay %d", n)
	}
}

func TestSlowAttackOutsideWindowIsNotFlaggedByWindowRules(t *testing.T) {
	// Sin la regla de ataque lento (-1), 1 fallo cada 2 minutos no dispara nada:
	// nunca hay 5 fallos dentro de una ventana de 5 minutos.
	d := New(Config{SlowFailures: -1})
	for i := 0; i < 30; i++ {
		d.Process(fail("203.0.113.1", "root", time.Duration(i)*2*time.Minute))
	}
	if n := len(d.Alerts()); n != 0 {
		t.Fatalf("las reglas con ventana no deberían alertar, hay %d", n)
	}
	// Con una ventana más amplia sí se detecta como fuerza bruta.
	d2 := New(Config{Window: 15 * time.Minute, SlowFailures: -1})
	for i := 0; i < 30; i++ {
		d2.Process(fail("203.0.113.1", "root", time.Duration(i)*2*time.Minute))
	}
	if len(d2.Alerts()) == 0 {
		t.Fatal("con ventana de 15 min debería detectarse")
	}
}

func TestPasswordSpraying(t *testing.T) {
	d := New(DefaultConfig())
	for i, u := range []string{"admin", "test", "oracle", "ubuntu"} { // 4 usuarios, 1 intento cada uno
		d.Process(fail("198.51.100.9", u, time.Duration(i)*10*time.Second))
	}
	m := rules(d)
	spray := m[RuleSpraying+"|198.51.100.9"]
	if spray == nil || spray.Severity != Medium || len(spray.Users) != 4 {
		t.Fatalf("rociado: %+v", spray)
	}
	if m[RuleBruteForce+"|198.51.100.9"] != nil {
		t.Fatal("4 fallos no alcanzan el umbral de fuerza bruta")
	}
}

func TestSprayingEscalatesWithManyUsers(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 15; i++ {
		d.Process(fail("198.51.100.9", fmt.Sprintf("user%d", i), time.Duration(i)*time.Second))
	}
	if a := rules(d)[RuleSpraying+"|198.51.100.9"]; a == nil || a.Severity != High {
		t.Fatalf("15 usuarios distintos deberían ser severidad alta: %+v", a)
	}
}

func TestSuccessAfterFailuresIsCritical(t *testing.T) {
	d := New(DefaultConfig())
	feed(d,
		fail("192.0.2.77", "ana", 0),
		fail("192.0.2.77", "ana", 5*time.Second),
		fail("192.0.2.77", "ana", 10*time.Second),
		ok("192.0.2.77", "ana", 15*time.Second),
	)
	a := rules(d)[RuleCompromise+"|192.0.2.77"]
	if a == nil || a.Severity != Critical || a.Targeted != "ana" || a.Attempts != 3 || a.Method != "password" {
		t.Fatalf("alerta crítica esperada: %+v", a)
	}
	if d.Alerts()[0].Rule != RuleCompromise {
		t.Fatal("la crítica debe ir primera")
	}
}

func TestLegitimateLoginDoesNotAlert(t *testing.T) {
	d := New(DefaultConfig())
	// Un usuario se equivoca 1 vez de contraseña y entra.
	feed(d, fail("10.0.0.5", "ana", 0), ok("10.0.0.5", "ana", 4*time.Second))
	// Otro entra a la primera.
	feed(d, ok("10.0.0.6", "luis", time.Minute))
	if n := len(d.Alerts()); n != 0 {
		t.Fatalf("no esperaba alertas, hay %d: %+v", n, d.Alerts())
	}
}

func TestSuccessFromDifferentIPDoesNotAlert(t *testing.T) {
	d := New(DefaultConfig())
	feed(d,
		fail("203.0.113.1", "ana", 0), fail("203.0.113.1", "ana", 1*time.Second), fail("203.0.113.1", "ana", 2*time.Second),
		ok("192.0.2.200", "ana", 3*time.Second), // otra IP
	)
	if a := rules(d)[RuleCompromise+"|192.0.2.200"]; a != nil {
		t.Fatalf("no debe vincular IPs distintas: %+v", a)
	}
}

func TestOldFailuresDoNotTaintLaterLogin(t *testing.T) {
	d := New(DefaultConfig())
	feed(d,
		fail("192.0.2.5", "ana", 0), fail("192.0.2.5", "ana", time.Second), fail("192.0.2.5", "ana", 2*time.Second),
		ok("192.0.2.5", "ana", 20*time.Minute), // mucho después: fuera de la ventana
	)
	if a := rules(d)[RuleCompromise+"|192.0.2.5"]; a != nil {
		t.Fatalf("fallos fuera de ventana no deben contar: %+v", a)
	}
}

func TestIPsAreTrackedIndependently(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 3; i++ { // 3 + 3 = 6 fallos, pero repartidos en dos IPs
		d.Process(fail("203.0.113.1", "root", time.Duration(i)*time.Second))
		d.Process(fail("203.0.113.2", "root", time.Duration(i)*time.Second))
	}
	if n := len(d.Alerts()); n != 0 {
		t.Fatalf("cada IP está bajo el umbral, hay %d alertas", n)
	}
}

func TestInvalidUserCounting(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 5; i++ {
		e := fail("203.0.113.1", "admin", time.Duration(i)*time.Second)
		e.InvalidUser = true
		d.Process(e)
	}
	if a := d.Alerts()[0]; a.InvalidFr != 5 {
		t.Fatalf("InvalidFr=%d", a.InvalidFr)
	}
}

func TestStats(t *testing.T) {
	d := New(DefaultConfig())
	feed(d, fail("203.0.113.1", "root", 0), fail("203.0.113.1", "root", time.Second), fail("203.0.113.2", "admin", 2*time.Second), ok("10.0.0.1", "ana", 3*time.Second))
	s := d.Stats()
	if s.Events != 4 || s.Failed != 3 || s.Accepted != 1 || s.UniqueIPs != 3 ||
		s.TopIPs["203.0.113.1"] != 2 || s.TopUsers["root"] != 2 || !s.First.Equal(t0) || !s.Last.Equal(t0.Add(3*time.Second)) {
		t.Fatalf("stats: %+v", s)
	}
}

// El atacante controla cuántos usuarios distintos inventa: la memoria debe tener tope.
func TestMemoryIsBounded(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 10_000; i++ {
		d.Process(fail("203.0.113.1", fmt.Sprintf("user-%d", i), time.Duration(i)*time.Millisecond))
	}
	for _, a := range d.Alerts() {
		if len(a.Users) > maxUsersPerAlert {
			t.Fatalf("la alerta %s guarda %d usuarios (tope %d)", a.Rule, len(a.Users), maxUsersPerAlert)
		}
	}
}

func TestGCRemovesIdleState(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 100; i++ {
		d.Process(fail(fmt.Sprintf("203.0.113.%d", i), "root", 0))
	}
	// Mucho después, llegan eventos suficientes para disparar la limpieza.
	for i := 0; i < gcEvery; i++ {
		d.Process(fail("198.51.100.1", "root", 2*time.Hour))
	}
	if len(d.ips) > 2 {
		t.Fatalf("las IPs inactivas debían limpiarse; quedan %d", len(d.ips))
	}
}

// Un atacante que manda cientos de miles de intentos NO debe poder ralentizar el análisis
// (antes el cálculo era cuadrático: 10.000 eventos tardaban 5 segundos).
func TestAnalysisStaysFastUnderFlood(t *testing.T) {
	d := New(DefaultConfig())
	start := time.Now()
	for i := 0; i < 200_000; i++ {
		d.Process(fail("203.0.113.1", fmt.Sprintf("u%d", i%500), time.Duration(i)*time.Millisecond))
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("200.000 eventos tardaron %v: el análisis no escala", el)
	}
	if st := d.ips["203.0.113.1"]; st.count() > maxFailsPerIP {
		t.Fatalf("la memoria por IP debe tener tope: %d", st.count())
	}
}

func TestSlowScanDetectedWhenWindowRulesMiss(t *testing.T) {
	d := New(DefaultConfig())
	// 30 intentos, uno cada 4 minutos: nunca hay 5 dentro de 5 minutos.
	for i := 0; i < 30; i++ {
		d.Process(fail("203.0.113.200", "root", time.Duration(i)*4*time.Minute))
	}
	m := rules(d)
	slow := m[RuleSlow+"|203.0.113.200"]
	if slow == nil || slow.Severity != Medium || slow.Attempts != 30 {
		t.Fatalf("esperaba alerta de ataque lento con 30 intentos: %+v", slow)
	}
	if m[RuleBruteForce+"|203.0.113.200"] != nil {
		t.Fatal("no debería haber alerta de fuerza bruta con ventana")
	}
}

func TestSlowScanNotDuplicatedWhenBruteForceAlreadyCoversIt(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 50; i++ {
		d.Process(fail("203.0.113.1", "root", time.Duration(i)*time.Second))
	}
	if a := rules(d)[RuleSlow+"|203.0.113.1"]; a != nil {
		t.Fatalf("la fuerza bruta ya cubre esta IP: %+v", a)
	}
}

func TestSlowScanBelowThresholdAndDisabled(t *testing.T) {
	d := New(DefaultConfig())
	for i := 0; i < 19; i++ {
		d.Process(fail("203.0.113.8", "root", time.Duration(i)*time.Hour))
	}
	if len(d.Alerts()) != 0 {
		t.Fatal("19 intentos no alcanzan el umbral de 20")
	}
	off := New(Config{SlowFailures: -1})
	for i := 0; i < 100; i++ {
		off.Process(fail("203.0.113.8", "root", time.Duration(i)*time.Hour))
	}
	if len(off.Alerts()) != 0 {
		t.Fatal("con -1 la regla debe estar desactivada")
	}
}
