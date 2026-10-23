# Route ground-truth sandbox (PLAN.md §7 layer 1, ADR 005).
#
# Build stage installs the benchmark repo's own dependencies (needs network, runs only on pinned
# corpus repos, never on PR code). The dump itself runs with `--network none`, read-only rootfs,
# no capabilities and as nobody; see eval/tools/route_truth.py for the exact `docker run` flags.
ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1

# System build dependencies some repos need for their wheels (e.g. python-ldap), space-separated.
ARG APT_PACKAGES=""
RUN if [ -n "$APT_PACKAGES" ]; then apt-get update -q && \
    apt-get install -yq --no-install-recommends $APT_PACKAGES && rm -rf /var/lib/apt/lists/*; fi

# Optional corporate/proxy CA for the build stage only (route_truth.py --ca-bundle); empty otherwise.
COPY build-ca.crt /build-ca.crt

COPY src/ /src/
COPY install_deps.sh /install_deps.sh
ARG APP_DIR=.
ARG INSTALL_SELF=0
RUN if [ -s /build-ca.crt ]; then export PIP_CERT=/build-ca.crt; fi; \
    sh /install_deps.sh "/src/${APP_DIR}" && rm -f /build-ca.crt

# Directories the app expects at import time (e.g. built frontend assets), space-separated.
ARG MKDIRS=""
ARG TOUCH=""
RUN for d in $MKDIRS; do mkdir -p "/src/$d"; done; \
    for f in $TOUCH; do mkdir -p "$(dirname "/src/$f")" && touch "/src/$f"; done

COPY dump_routes.py /dump_routes.py
USER 65534:65534
WORKDIR /src
ENTRYPOINT ["python", "/dump_routes.py", "/src"]
