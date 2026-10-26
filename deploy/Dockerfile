# One image for the `api` and `worker` processes (PLAN.md §5 deployment). The command decides:
#   api:    uvicorn accessguard_app.api.asgi:app --host 0.0.0.0 --port 8000
#   worker: arq accessguard_app.jobs.worker.HighWorker   (and LowWorker)
#   verifier: arq accessguard_app.jobs.worker.VerifyWorker (ADR 015; holds the vault private key)
# The worker only parses fetched source (ADR 005); it never installs or runs it.
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock ./
COPY packages/authgraph packages/authgraph
COPY packages/app packages/app
COPY packages/verifier packages/verifier
RUN uv sync --locked --no-dev --package accessguard-app

FROM python:3.12-slim
RUN useradd --system --uid 10001 accessguard
COPY --from=build /src /src
ENV PATH="/src/.venv/bin:$PATH" PYTHONUNBUFFERED=1
WORKDIR /src/packages/app
USER accessguard
EXPOSE 8000
CMD ["uvicorn", "accessguard_app.api.asgi:app", "--host", "0.0.0.0", "--port", "8000"]
