# Developer entry points. CI runs the same targets (.github/workflows/ci.yml).
UV ?= uv
BASELINE ?=

.PHONY: install test lint format typecheck check eval eval-gates eval-routes corpus route-truth fixtures replay

install:
	$(UV) sync

test:
	$(UV) run pytest -q

lint:
	$(UV) run ruff check .
	$(UV) run ruff format --check .

format:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

typecheck:
	$(UV) run mypy packages/authgraph

check: lint typecheck test

# Per-rule precision/recall on the labelled corpus. BASELINE=path/to/report.json adds the
# no-regression check against another report (CI passes main's report).
eval:
	$(UV) run python eval/harness.py $(if $(BASELINE),--baseline $(BASELINE))

eval-gates:
	$(UV) run python eval/harness.py --enforce-gates $(if $(BASELINE),--baseline $(BASELINE))

# Route recall vs sandbox ground truth: fetches only the repos that have a truth file.
eval-routes:
	$(UV) run python eval/tools/fetch_corpus.py $(basename $(notdir $(wildcard eval/corpus/truth/*.json)))
	$(UV) run python eval/harness.py --routes --enforce-gates --out eval/reports/routes

# Real-history replay of one corpus repo (precision check): make replay REPO=dispatch
replay:
	$(UV) run python eval/tools/replay_history.py $(REPO) --commits 300

corpus:
	$(UV) run python eval/tools/fetch_corpus.py

route-truth:
	$(UV) run python eval/tools/route_truth.py

fixtures:
	$(UV) run python eval/tools/gen_mutations.py eval/mutations
