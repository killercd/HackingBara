FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends hydra \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/pyproject.toml backend/requirements.lock ./
RUN python -c "import subprocess,tomllib; subprocess.check_call(['pip','install','--no-cache-dir','-c','requirements.lock',*tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']])" \
    && useradd -m -u 10001 app

FROM runtime AS api
COPY backend/app app
RUN pip install --no-cache-dir --no-deps .
COPY backend/alembic.ini .
COPY backend/migrations migrations
USER app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers"]

FROM rust:1.85-bookworm AS rustscan
RUN cargo install rustscan --version 2.4.1 --locked

FROM golang:1.23-bookworm AS gobuster
RUN CGO_ENABLED=0 go install github.com/OJ/gobuster/v3@v3.6.0

FROM runtime AS scanner-tools
RUN apt-get update && apt-get install -y --no-install-recommends nmap chromium chromium-driver git xvfb ca-certificates bash coreutils grep sed gawk \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rustscan /usr/local/cargo/bin/rustscan /usr/local/bin/rustscan
COPY --from=gobuster /go/bin/gobuster /usr/local/bin/gobuster
ARG EYEWITNESS_REV=c3286fb71406e0b55b85a7c38dac76ee50b0f955
RUN git init /opt/eyewitness && cd /opt/eyewitness && git remote add origin https://github.com/RedSiege/EyeWitness.git \
    && git fetch --depth 1 origin "$EYEWITNESS_REV" && git checkout FETCH_HEAD \
    && pip install --no-cache-dir -c /app/requirements.lock -r setup/requirements.txt && rm -rf .git
ARG EXPLOITDB_REV=70bbef3f18b835b0d8bacb978f2bc7b751a7cec9
RUN git init /opt/exploitdb && cd /opt/exploitdb \
    && git remote add origin https://gitlab.com/exploit-database/exploitdb.git \
    && git config core.sparseCheckout true \
    && printf '/searchsploit\n/.searchsploit_rc\n/files_exploits.csv\n/files_shellcodes.csv\n' > .git/info/sparse-checkout \
    && git fetch --depth 1 --filter=blob:none origin "$EXPLOITDB_REV" && git checkout FETCH_HEAD \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && rm -rf .git
COPY docker/patch_eyewitness.py /tmp/patch_eyewitness.py
RUN python /tmp/patch_eyewitness.py \
    && printf '#!/bin/sh\nexec python /opt/eyewitness/Python/EyeWitness.py "$@"\n' > /usr/local/bin/eyewitness \
    && chmod +x /usr/local/bin/eyewitness \
    && mkdir -p /evidence && chown app:app /evidence

FROM scanner-tools AS worker
COPY backend/app app
RUN pip install --no-cache-dir --no-deps .
COPY backend/alembic.ini .
COPY backend/migrations migrations
USER app
CMD ["celery", "-A", "app.tasks:celery", "worker", "--loglevel=WARNING", "--concurrency=2"]
