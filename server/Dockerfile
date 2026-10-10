# ============================================================
# SecureScan Pro v3.1.3 — Dockerfile (backend API)
#
# CORRECCIONES:
#  1. Añadido wkhtmltopdf — requerido por pdfkit para generar PDFs
#  2. Gunicorn usa GUNICORN_TIMEOUT (env) — soporta escaneos >120s
#  3. Nuclei templates se copian/apuntan a /home/scanner/nuclei-templates
#     (coincide con el volumen del docker-compose)
#  4. Añadido gevent para workers async (maneja muchos escaneos concurrentes)
#  5. Añadido libcap2-bin para dar NET_RAW a nmap sin root completo
#  6. Script entrypoint.sh para inicialización robusta
# ============================================================

FROM python:3.11-slim-bookworm

# NVD_API_KEY opcional para el build (acelera la pre-descarga de la base de
# Dependency-Check más abajo). Independiente de la variable de entorno del
# mismo nombre en runtime -- los build args de Docker no heredan el .env de
# docker-compose automáticamente. Para usarla acá: `docker build --build-arg
# NVD_API_KEY=tu_key ...` (opcional, el build funciona igual sin ella).
ARG NVD_API_KEY=""

LABEL maintainer="SecureScan Pro Team"
LABEL version="3.1.3"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONFAULTHANDLER=1

# ── Sistema base ─────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    patator \
    curl \
    wget \
    ca-certificates \
    git \
    unzip \
    nodejs \
    npm \
    python3 \
    python3-pip \
    # BUG FIX: wkhtmltopdf es requerido por pdfkit para generar PDFs
    wkhtmltopdf \
    xvfb \
    # Para dar capacidades de red a nmap corriendo como usuario no-root
    libcap2-bin \
    # Java -- requerido por OWASP Dependency-Check (Grupo 3, análisis de código)
    openjdk-17-jre-headless \
    # hexdump -- requerido por testssl.sh real (Grupo 1, Huella Digital),
    # error fatal sin esto ("You need to install hexdump for this program to work")
    bsdmainutils \
    # dig/host -- testssl.sh también los requiere ("Neither dig, host, drill nor nslookup is present")
    dnsutils \
    # ps -- requerido por testssl.sh real (Grupo 1, Huella Digital)
    procps \
    && rm -rf /var/lib/apt/lists/*

# ── Go 1.22 (manual — golang-go de bookworm es 1.19, incompatible) ──
RUN curl -fsSL https://go.dev/dl/go1.22.5.linux-amd64.tar.gz \
    | tar -C /usr/local -xz
ENV GOPATH=/go
ENV PATH="/usr/local/go/bin:${GOPATH}/bin:/usr/local/bin:${PATH}"

# ── SQLMap ───────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && ln -s /opt/sqlmap/sqlmapapi.py /usr/local/bin/sqlmapapi.py

# ── Semgrep (Grupo 3, análisis de código -- SAST real) ────
# El registro de reglas de semgrep.dev puede estar bloqueado en redes con
# egress restringido (confirmado en pruebas) -- por eso se clona el repo
# público de reglas (github.com/semgrep/semgrep-rules) directo y se
# consolidan los YAML de la carpeta "security" de los lenguajes más
# comunes en apps web en una sola carpeta plana. Un solo --config con
# todo consolidado es mucho más rápido en runtime que apuntar a decenas
# de carpetas por separado (confirmado: pasar de 91 --config a 1 bajó
# el tiempo de carga de reglas de forma notoria).
COPY scripts/consolidate_semgrep_rules.py /tmp/consolidate_semgrep_rules.py
RUN pip install --no-cache-dir --break-system-packages semgrep \
    && git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /tmp/semgrep-rules \
    && python3 /tmp/consolidate_semgrep_rules.py /tmp/semgrep-rules /opt/semgrep-rules 400 \
    && rm -rf /tmp/semgrep-rules /tmp/consolidate_semgrep_rules.py

# ── testssl.sh real (Grupo 1, Huella Digital) ─────────────
# Reemplaza al equivalente ligero en Python -- este SÍ prueba las
# vulnerabilidades con nombre propio (Heartbleed, POODLE, BEAST, etc.)
# El repo trae binarios de OpenSSL propios para protocolos legados que
# el OpenSSL del sistema ya no soporta -- no hace falta ningún paso extra.
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ── Trivy (Grupo 3, análisis de código -- dependencias + imágenes Docker) ──
# ANCLADO a v0.72.0 a propósito, NO "latest": Trivy sufrió dos incidentes
# reales de cadena de suministro en marzo 2026 (credenciales comprometidas
# publicaron releases maliciosos). v0.72.0 es posterior, firmada y
# verificada. Revisar releases nuevas manualmente antes de subir la versión.
# Se descarga directo del release de GitHub (no del script oficial de
# install, que redirige a get.trivy.dev -- ese dominio puede estar
# bloqueado en redes con egress restringido).
RUN curl -fsSL -o /tmp/trivy.tar.gz \
    https://github.com/aquasecurity/trivy/releases/download/v0.72.0/trivy_0.72.0_Linux-64bit.tar.gz \
    && tar xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz

# Pre-descargar la base de datos de vulnerabilidades de Trivy EN EL BUILD --
# sin esto, cada contenedor nuevo necesita bajarla en runtime desde
# mirror.gcr.io (varios cientos de MB), lo que agrega latencia real al
# primer escaneo y una dependencia de red que no es obvia. Queda
# horneada en la imagen. Se actualiza sola en runtime cuando haga falta.
RUN trivy fs --download-db-only --cache-dir /opt/trivy-cache || true

# ── OWASP Dependency-Check (Grupo 3, análisis de código -- dependencias) ──
# v12.2.2 (mayo 2026) -- para versiones más nuevas: comparar contra
# https://dependency-check.github.io/DependencyCheck/current.txt
RUN curl -fsSL -o /tmp/dependency-check.zip \
    https://github.com/dependency-check/DependencyCheck/releases/download/v12.2.2/dependency-check-12.2.2-release.zip \
    && unzip -q /tmp/dependency-check.zip -d /opt \
    && rm /tmp/dependency-check.zip \
    && ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh

# Base NVD en un directorio ESCRIBLE por el usuario `scanner` (el de la app).
# Antes vivía en /opt/dependency-check/data (propiedad de root): el proceso no
# podía tomar el candado exclusivo de H2 y fallaba con "Unable to obtain an
# exclusive lock on the H2 database". Se monta como volumen persistente
# (docker-compose: dependency-check-data) para que sobreviva a los rebuilds.
ENV DEPENDENCY_CHECK_DATA=/opt/dependency-check-data
RUN mkdir -p /opt/dependency-check-data

# Intento OPCIONAL de pre-poblar la base en el build. Con NVD_API_KEY suele
# funcionar; sin ella NVD rechaza/limita y la base queda vacía -- por eso el
# código de la app (dependency_check.ensure_database) la sincroniza en segundo
# plano al arrancar si está vacía o vieja, y mientras tanto el paso se marca
# "skipped" con un mensaje claro en vez de fingir que no hay vulnerabilidades.
RUN if [ -n "$NVD_API_KEY" ]; then \
    dependency-check.sh --updateonly --data /opt/dependency-check-data --disableVersionCheck --nvdApiKey "$NVD_API_KEY" || echo "aviso: no se pudo pre-poblar la base NVD en el build"; \
    else \
    echo "aviso: sin NVD_API_KEY en el build -- la base NVD se sincroniza al arrancar el contenedor"; \
    fi

# ── Herramientas Go ───────────────────────────────────────
# gobuster v3.6.0 (v3.8.2 requiere directiva 'tool' de Go 1.24)
# ffuf v2 requiere módulo path correcto: ffuf/v2
# nuclei v3.2.4 — versión estable probada
# gitleaks (Grupo 3, análisis de código) -- @latest acá es seguro porque
# "go install" resuelve contra el proxy de módulos de Go, no contra la
# API de GitHub (que rate-limitea IPs no autenticadas). Ruta del módulo
# = github.com/zricethezav/gitleaks/v8 -- la organización de GitHub se
# renombró a "gitleaks", pero el go.mod interno del proyecto SIGUE
# declarándose bajo "zricethezav" -- usar la ruta nueva de GitHub aquí
# rompe la resolución de Go con un conflicto de "module declares path".
RUN go install github.com/OJ/gobuster/v3@v3.6.0 \
    && go install github.com/ffuf/ffuf/v2@v2.1.0 \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.2.4 \
    && go install github.com/zricethezav/gitleaks/v8@latest \
    && go clean -modcache || true \
    && cp /go/bin/gobuster    /usr/local/bin/ \
    && cp /go/bin/ffuf        /usr/local/bin/ \
    && cp /go/bin/nuclei      /usr/local/bin/ \
    && cp /go/bin/gitleaks    /usr/local/bin/

# ── TruffleHog (binario oficial precompilado, Grupo 3) ────
# FIX: "go install .../trufflehog/v3@latest" falla siempre -- el go.mod
# real de TruffleHog trae directivas "replace" que el toolchain de Go
# rechaza al instalarlo como módulo remoto ("must not contain directives
# that would cause it to be interpreted differently than if it were the
# main module"). Es un problema conocido del propio proyecto, no una
# mala versión. Se resuelve igual que Trivy: bajando el binario oficial
# ya compilado desde GitHub Releases en vez de compilarlo con "go install".
RUN TRUFFLEHOG_VERSION=$(curl -fsSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep -oP '"tag_name":\s*"v\K[^"]+') \
    && curl -fsSL -o /tmp/trufflehog.tar.gz \
    "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
    && tar xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog \
    && rm /tmp/trufflehog.tar.gz

# ── Wappalyzer ───────────────────────────────────────────
RUN pip install --no-cache-dir python-Wappalyzer requests beautifulsoup4

# ── Wordlists (SecLists) ──────────────────────────────────
# Descarga solo los archivos que usa el proyecto (en vez de clonar SecLists
# completo, >1 GB, que falla por cortes de red). common.txt es obligatorio;
# el resto se intenta y, si no existe, el codigo cae al wordlist secundario.
RUN set -e; \
    BASE=https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content; \
    DEST=/opt/SecLists/Discovery/Web-Content; \
    mkdir -p "$DEST/CMS" "$DEST/api"; \
    for f in common.txt CMS/wordpress.fuzz.txt api/api-endpoints.txt; do \
        curl -fsSL --retry 8 --retry-delay 5 --retry-all-errors --connect-timeout 20 "$BASE/$f" -o "$DEST/$f"; \
    done; \
    for f in IIS.fuzz.txt NodeJS.fuzz.txt django.txt laravel.txt spring-boot.txt; do \
        curl -fsSL --retry 3 --retry-delay 3 --connect-timeout 20 "$BASE/$f" -o "$DEST/$f" || echo "aviso: $f no disponible, se omite"; \
    done; \
    mkdir -p /usr/share/wordlists/dirb \
    && ln -s /opt/SecLists /usr/share/wordlists/seclists \
    && ln -s /opt/SecLists/Discovery/Web-Content/common.txt /usr/share/wordlists/dirb/common.txt

# ── Searchsploit ─────────────────────────────────────────
RUN for i in 1 2 3 4 5; do \
        git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && break; \
        echo "git clone fallo (intento $i), reintentando..."; rm -rf /opt/exploitdb; sleep 10; \
    done; \
    test -d /opt/exploitdb/.git \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# ── theHarvester real (Grupo 2, OSINT) ─────────────────────
# Requiere Python 3.12+ y la imagen base es 3.11 -- se instala en un
# entorno aislado con 'uv' (que el propio proyecto ya usa para su build)
# en vez de tocar el Python 3.11 del resto de la app. El paquete
# "theHarvester" en PyPI está abandonado (v0.0.1, no es el real) --
# la instalación real es directo desde el repo de GitHub.
#
# FIX: UV_PYTHON_INSTALL_DIR -- por defecto "uv python install" pone el
# intérprete en /root/.local/share/uv/python/..., y el symlink
# .../bin/python del venv apunta ahí. Como el contenedor corre como
# usuario "scanner" (no root) y /root no es atravesable para nadie más,
# CUALQUIER chmod sobre el venv era inútil: el proceso nunca lograba ni
# siquiera llegar hasta el intérprete real ([Errno 13] Permission
# denied). Se instala en /opt/uv-python en vez de dentro de /root.
ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python
# FIX: theHarvester (paquete "theharvester" en su pyproject.toml) subió su
# requisito mínimo a Python>=3.14 -- 3.12 ya no es suficiente para
# resolver sus dependencias ("No solution found... depends on Python>=3.14").
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && /root/.local/bin/uv python install 3.14 \
    && git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester \
    && /root/.local/bin/uv venv --python 3.14 /opt/theHarvester-venv \
    && /root/.local/bin/uv pip install --python /opt/theHarvester-venv/bin/python /opt/theHarvester \
    && ln -s /opt/theHarvester-venv/bin/theHarvester /usr/local/bin/theHarvester \
    && chmod -R a+rX /opt/theHarvester-venv /opt/theHarvester /opt/uv-python \
    # FIX: "a+rX" solo agrega +x a lo que YA era ejecutable para alguien.
    # El script generado por "uv pip install" no siempre nace así, lo que
    # producía [Errno 13] Permission denied al invocar theHarvester como
    # usuario no-root. chmod +x explícito, sin condiciones, sobre todo
    # /bin del venv (incluye el propio theHarvester y el intérprete python
    # del que depende su shebang).
    && chmod +x /opt/theHarvester-venv/bin/*

# ── Usuario ──────────────────────────────────────────────
RUN groupadd -r scanner && useradd -r -g scanner -d /home/scanner -m -s /bin/bash scanner \
    && chown -R scanner:scanner /opt/dependency-check-data

# BUG FIX: dar capacidades de red a nmap para que funcione sin root
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap || true

WORKDIR /app

# ── Python deps ──────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    # BUG FIX: gevent para workers async (escaneos concurrentes)
    && pip install --no-cache-dir gunicorn gevent

# ── App ──────────────────────────────────────────────────
COPY --chown=scanner:scanner . .
RUN chmod -R 755 /app

# ── Templates Nuclei ─────────────────────────────────────
# BUG FIX: path correcto — coincide con el volumen del docker-compose
USER root
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates \
    /home/scanner/nuclei-templates \
    && chown -R scanner:scanner /home/scanner/nuclei-templates

# Permisos para nuclei config y templates
RUN mkdir -p /home/scanner/.config/nuclei \
    && echo "nuclei-templates-directory: /home/scanner/nuclei-templates" \
    > /home/scanner/.config/nuclei/config.yaml \
    && chown -R scanner:scanner /home/scanner/.config \
    && chown -R scanner:scanner /home/scanner/nuclei-templates \
    && chmod -R 755 /home/scanner/.config

# ── Directorio de reportes ────────────────────────────────
RUN mkdir -p /app/reports && chown -R scanner:scanner /app/reports

# ── Entrypoint script ─────────────────────────────────────
COPY --chown=scanner:scanner entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# ── Volver a usuario seguro ──────────────────────────────
USER scanner

# ── Wordlists propias del proyecto ──────────────────────────
COPY --chown=scanner:scanner wordlists/ /app/wordlists/
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# timeout configurable vía env (default 3600s para escaneos largos)
# sync worker con threads — no requiere gevent, funciona en cualquier entorno
CMD ["sh", "-c", "\
    gunicorn \
    --bind              0.0.0.0:5000 \
    --workers           2 \
    --threads           4 \
    --worker-class      sync \
    --worker-tmp-dir    /dev/shm \
    --timeout           ${GUNICORN_TIMEOUT:-3600} \
    --graceful-timeout  30 \
    --keep-alive        5 \
    --log-level         info \
    --access-logfile    - \
    --error-logfile     - \
    app:app"]