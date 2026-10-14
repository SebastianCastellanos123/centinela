# ATACANTE DE PRUEBA: solo debe apuntar al contenedor "target" de este laboratorio.
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends hydra openssh-client sshpass \
 && rm -rf /var/lib/apt/lists/*
COPY wordlist.txt users.txt /lab/
WORKDIR /lab
CMD ["sleep", "infinity"]
