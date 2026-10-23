# Express route ground-truth sandbox (PLAN.md §7 layer 1, Phase 3; ADR 005).
#
# Build stage installs the pinned benchmark repo's own npm dependencies with lifecycle scripts
# disabled (needs network; never runs on PR code). The dump runs with `--network none`, no
# capabilities and as the unprivileged `node` user; see eval/tools/route_truth.py for the `docker run` flags.
FROM node:22-bookworm-slim

# Optional corporate/proxy CA for the build stage only (route_truth.py --ca-bundle); empty otherwise.
COPY build-ca.crt /build-ca.crt
# tsx is installed globally as root; everything else runs as the image's unprivileged `node` user.
RUN if [ -s /build-ca.crt ]; then export NODE_EXTRA_CA_CERTS=/build-ca.crt; fi; \
    npm install -g --no-audit --no-fund --loglevel=error tsx@4.20.6
COPY --chown=node:node src/ /src/
USER node
ARG APP_DIR=.
# tsx (https://tsx.is/node) loads TypeScript entry points: `node --import tsx` registers its
# CommonJS and ESM hooks.
RUN if [ -s /build-ca.crt ]; then export NODE_EXTRA_CA_CERTS=/build-ca.crt; fi; \
    cd "/src/${APP_DIR}" && \
    (npm ci --ignore-scripts --no-audit --no-fund --loglevel=error || \
     npm install --ignore-scripts --no-audit --no-fund --loglevel=error)

COPY dump_routes.js /dump_routes.js
WORKDIR /src
ENTRYPOINT ["node", "--import", "tsx", "/dump_routes.js"]
