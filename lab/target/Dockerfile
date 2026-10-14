# SERVIDOR SSH DE PRUEBA: contiene una contraseña débil A PROPÓSITO (usuario "deploy").
# Solo para el laboratorio local. No publica ningún puerto hacia tu red.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server rsyslog \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /var/log/ssh-lab

# Cuentas: root con clave aleatoria (el ataque de fuerza bruta contra root FALLA) y
# "deploy" con una contraseña débil que aparece en la lista de palabras del atacante.
RUN useradd -m -s /bin/bash deploy \
 && echo "deploy:letmein" | chpasswd \
 && echo "root:$(head -c 24 /dev/urandom | base64)" | chpasswd \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/; s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.sh /entrypoint.sh
RUN sed -i "s/\r$//" /entrypoint.sh && chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
