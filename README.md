# Centinela

Detector de ataques SSH en logs de Linux, escrito en Go **sin dependencias externas**. Lee `auth.log` (o la salida de `journalctl`), encuentra fuerza bruta, rociado de contraseñas, ataques lentos y, sobre todo, **accesos exitosos que llegan después de muchos fallos** (la señal de que un atacante pudo entrar). Funciona sobre un archivo completo o en vivo, como `tail -f`.

Centinela solo **lee** logs: nunca bloquea, ni modifica, ni ejecuta nada. Te sugiere qué hacer y tú decides.

```
CENTINELA · informe de accesos SSH
============================================================
Período:        2026-10-12 03:12:00 → 2026-10-12 18:05:18
Líneas leídas:  164 (eventos SSH: 112, ignoradas: 52)
Fallos:         108   Accesos exitosos: 4   IPs distintas: 8


ALERTAS (8)

[CRÍTICA] Acceso exitoso tras fallos (posible compromiso)
   IP: 192.0.2.77
   Cuándo: 2026-10-12 05:55:30 → 2026-10-12 05:55:30 (instantáneo)
   Entró como "deploy" por password tras 6 fallos recientes
   Usuarios probados: deploy (6)

[ALTA] Fuerza bruta
   IP: 203.0.113.50
   Cuándo: 2026-10-12 03:12:08 → 2026-10-12 03:13:28 (1m20s)
   Intentos: 45
   Usuarios probados: root (45)

[MEDIA] Ataque lento (intentos espaciados en el tiempo)
   IP: 203.0.113.200
   Cuándo: 2026-10-12 14:00:00 → 2026-10-12 15:56:00 (1h56m0s)
   Intentos: 30
   Usuarios probados: root (30)

[...]
```

## Qué detecta

| Regla | Qué significa | Severidad |
|---|---|---|
| `success_after_failures` | Una IP entra con éxito después de varios fallos recientes: **posible compromiso** | Crítica |
| `brute_force` | Muchos fallos desde una IP en poco tiempo (por defecto 5 en 5 min) | Media; alta con 4× el umbral |
| `password_spraying` | Una IP prueba muchos usuarios distintos (por defecto 4 en 5 min) | Media; alta con 3× el umbral |
| `slow_scan` | Intentos espaciados en el tiempo que esquivan las reglas con ventana (por defecto 20 en total) | Media |

Un ataque que dura horas es **una** alerta con sus totales, no cientos de líneas repetidas. Las IPs con ataques ya cubiertos por fuerza bruta o rociado no se duplican como "ataque lento".

## Uso

Requisitos: Go 1.22 o superior.

```bash
go build -o centinela ./cmd/centinela

# Analizar un archivo (los .gz se leen solos)
./centinela /var/log/auth.log

# Varios archivos: del más antiguo al más reciente
./centinela /var/log/auth.log.2.gz /var/log/auth.log.1 /var/log/auth.log

# Desde journalctl (sistemas con systemd)
journalctl -u ssh -o short-iso | ./centinela -

# En vivo: avisa de las alertas apenas ocurren (Ctrl+C muestra el resumen)
./centinela -f /var/log/auth.log

# Otros formatos y umbrales
./centinela -format json -brute 10 -window 10m /var/log/auth.log
./centinela -format markdown /var/log/auth.log > informe.md
```

Las opciones van **antes** de los archivos. Prueba con el log de ejemplo: `./centinela -year 2026 -tz UTC testdata/auth.log`.

| Opción | Por defecto | Qué hace |
|---|---|---|
| `-format` | `text` | `text`, `json` o `markdown` |
| `-window` | `5m` | Ventana de tiempo para contar intentos |
| `-brute` | `5` | Fallos de una IP para alertar de fuerza bruta |
| `-spray` | `4` | Usuarios distintos de una IP para alertar de rociado |
| `-compromise` | `3` | Fallos previos para marcar un acceso exitoso como sospechoso |
| `-slow` | `20` | Fallos acumulados para alertar de ataque lento (`-1` desactiva) |
| `-f` | apagado | Modo en vivo (`-from-start` también analiza lo ya escrito) |
| `-year` | año actual | Año de los logs en formato syslog (que no trae año) |
| `-tz` | la del equipo | Zona horaria de logs sin zona, ej. `America/Bogota` |
| `-fail-on` | `none` | Sale con **código 2** si hay alertas de esa severidad o más (útil en scripts y cron) |

En Windows puedes analizar logs que hayas copiado de un servidor, o ejecutarlo dentro de WSL.

## Laboratorio: atácate a ti mismo

La carpeta [`lab/`](lab/README.md) levanta con Docker un servidor SSH débil a propósito, un atacante con `hydra` y Centinela, en una red interna aislada. Lanzas un ataque real, ves cómo queda en el log y cómo lo detecta Centinela. Instrucciones en [`lab/README.md`](lab/README.md).

## Decisiones de diseño y seguridad

Un detector de ataques también es un blanco, así que se diseñó pensando en que **el log lo controla el atacante**:

- **Inyección de logs.** El nombre de usuario lo escribe quien ataca y puede contener texto como `x from 8.8.8.8 port 22` para hacerte acusar a otra IP. El parser captura el usuario de forma *greedy* y ancla la expresión al final de la línea, de modo que la IP es siempre la última (la que añade `sshd`). Hay tests con este ataque y una mutación probada: al debilitar la expresión, el test falla.
- **Secuencias de escape en la terminal.** Un usuario como `\x1b[2J` podría borrar o falsificar tu pantalla. Todo texto que viene del log se sanea antes de mostrarse, y en Markdown se escapa para no romper tablas.
- **Resistencia a saturación.** La primera versión recalculaba los usuarios distintos recorriendo toda la ventana en cada evento: 10.000 intentos tardaban 5 segundos y el costo crecía al cuadrado, de modo que un atacante podía frenar al detector con el mismo ataque que intentaba detectar. Ahora los contadores son incrementales (O(1) por evento) y hay un test que procesa 200.000 eventos.
- **Memoria acotada.** Usuarios por alerta, fallos por IP y claves globales tienen tope, y se descarta el estado de IPs inactivas. El atacante controla cuántos usuarios e IPs aparecen.
- **Líneas gigantes.** Se recortan a 64 KB en vez de agotar memoria o abortar la lectura.
- **IPs y puertos validados.** Una línea con una IP inválida se descarta.
- **Sin dependencias** (solo la librería estándar): sin cadena de suministro que vigilar.
- **Rotación de logs.** El modo en vivo detecta cuando `logrotate` renombra el archivo (compara el *inode*) o lo trunca, y sigue leyendo sin perder líneas.

## Pruebas

```bash
go vet ./...
go test ./... -race -count=1 -cover
```

Cubren el parser (formatos syslog e ISO, IPv6, `sshd-session`, cambio de año, inyección de logs), el detector (umbrales, ventana, episodios, severidad, escaneo lento, topes de memoria, rendimiento), el modo en vivo (líneas parciales, rotación, truncado) y el programa completo (formatos, códigos de salida, stdin, `.gz`, errores de uso).

## Estructura

```
centinela/
├── cmd/centinela/        # programa principal y flags
├── internal/
│   ├── parser/           # línea de log → evento (con defensa anti-inyección)
│   ├── detector/         # reglas, ventanas deslizantes, episodios
│   ├── report/           # texto, JSON y Markdown; saneado de texto del atacante
│   └── follow/           # lectura de líneas y modo en vivo (rotación/truncado)
├── testdata/             # logs sintéticos con IPs reservadas para documentación (RFC 5737)
├── lab/                  # laboratorio Docker de ataque y defensa
└── Dockerfile
```

## Limitaciones conocidas

- Solo entiende **sshd** (mensajes de contraseña y clave pública). No analiza otros servicios.
- Las IPs se toman del log tal como están: detrás de un proxy o NAT pueden no ser la del atacante real.
- Un ataque **distribuido** (miles de IPs con pocos intentos cada una) no cruza los umbrales por IP. Una mejora futura es agrupar por usuario atacado desde muchas IPs.
- Los logs en formato syslog no traen año ni zona horaria: usa `-year` y `-tz` si no coinciden con tu equipo.
- Los eventos deben llegar en orden cronológico; si no, avisa por `stderr`.
- Es una herramienta de **análisis**, no de prevención. Para bloquear automáticamente existe `fail2ban`.

## Uso responsable

Usa Centinela y el laboratorio solo sobre sistemas **tuyos** o con autorización. Los logs reales contienen IPs y nombres de usuario de personas: trátalos como datos sensibles.

## Licencia

MIT
