# DeepAudit runner image: the full arsenal pre-installed so audits start tool-ready.
#
# The toolset is baked from lib/arsenal.py (the single source of truth) — `--print-all`
# emits the same idempotent install script the runtime uses. Rebuilt on arsenal changes and
# on a weekly schedule (to refresh nuclei templates and advisory data) by build-image.yaml.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    GOPATH=/root/go \
    GOTOOLCHAIN=local \
    LANG=C.UTF-8 \
    PATH=/usr/local/go/bin:/root/go/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin

# Base OS, language runtimes and build deps (libpcap-dev for naabu, ruby for wpscan).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python-is-python3 git curl wget sudo unzip jq \
        ca-certificates gnupg build-essential libpcap-dev ruby-full \
    && ln -sf /usr/bin/pip3 /usr/local/bin/pip \
    && rm -rf /var/lib/apt/lists/*

# Go toolchain (projectdiscovery tools need a recent Go).
RUN curl -fsSL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz | tar -C /usr/local -xz

# Node.js 20 (npm-based tools) and the GitHub CLI (the supervisor fans out worker runs with it).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && mkdir -p -m 755 /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs gh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Install the entire arsenal from the single source of truth. Kept as its own layer so the
# expensive tool builds are cached and only rebuilt when arsenal.py changes.
COPY lib/arsenal.py /app/lib/arsenal.py
COPY lib/__init__.py /app/lib/__init__.py
RUN python3 -m lib.arsenal --print-all > /tmp/install.sh \
    && bash /tmp/install.sh \
    && nuclei -update-templates -silent || true

# The rest of the code (the checkout at run time overrides this, but keep the image runnable).
COPY . /app

# Smoke: the core tools must be on PATH in the built image.
RUN for t in nuclei httpx subfinder katana ffuf nmap whatweb gh; do \
        command -v "$t" >/dev/null || { echo "MISSING: $t"; exit 1; }; done \
    && echo "arsenal ready"
