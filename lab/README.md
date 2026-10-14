# Laboratorio: ataque y defensa

Levanta un servidor SSH **vulnerable a propósito**, un atacante y Centinela, todo en una red Docker **interna** (sin acceso a Internet ni a tu red local). No se publica ningún puerto.

> El usuario `deploy` tiene la contraseña débil `letmein` a propósito. Esto es solo para el laboratorio. Nunca uses estas imágenes fuera de tu computador.

Requisitos: Docker Desktop corriendo. Todos los comandos se ejecutan desde la carpeta `lab/`.

## 1) Levantar el laboratorio

```bash
docker compose up -d --build target attacker
```

## 2) Ataque de fuerza bruta contra `root`

La contraseña de root es aleatoria, así que este ataque **falla**, pero deja huellas:

```bash
docker compose exec attacker hydra -l root -P /lab/wordlist.txt -t 4 ssh://target
```

## 3) Rociado de contraseñas (muchos usuarios, una contraseña)

```bash
docker compose exec attacker hydra -L /lab/users.txt -p password ssh://target
```

## 4) El caso grave: el atacante ENTRA

La contraseña de `deploy` está en la lista (es la última), así que hydra la encuentra después de decenas de fallos:

```bash
docker compose exec attacker hydra -l deploy -P /lab/wordlist.txt -t 4 ssh://target
```

## 5) Analizar con Centinela

```bash
docker compose run --rm centinela /var/log/ssh-lab/auth.log
```

Deberías ver alertas de fuerza bruta, de rociado y una **crítica** por el acceso exitoso de `deploy` tras los fallos. Si hydra no completó algún ataque (el servidor limita conexiones simultáneas), baja los hilos con `-t 1` o repite el comando.

Para verlo **en vivo**, abre dos terminales. En la primera:

```bash
docker compose run --rm centinela -f --from-start /var/log/ssh-lab/auth.log
```

Y en la segunda lanza de nuevo cualquiera de los ataques. Las alertas aparecen mientras ocurre el ataque.

También puedes pedir JSON o Markdown: `... centinela -format markdown /var/log/ssh-lab/auth.log`.

## 6) Ver el log crudo

```bash
docker compose exec target tail -n 20 /var/log/ssh-lab/auth.log
```

## Apagar y limpiar

```bash
docker compose down -v
```

## Ejercicios

1. Corre el paso 2 con `-t 1` (un intento a la vez) y luego con `-t 16`. ¿Cambia la severidad? ¿Por qué?
2. Sube la ventana a 30 minutos (`-window 30m`) y repite un ataque lento escribiendo tú mismo `ssh deploy@target` con contraseñas incorrectas, espaciadas.
3. Mitiga: edita `lab/target/Dockerfile` para poner `PasswordAuthentication no`, reconstruye y repite el paso 4. ¿Qué ve ahora Centinela?
