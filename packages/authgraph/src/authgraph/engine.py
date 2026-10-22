"""Engine pipeline per commit (PLAN.md §6.3): load -> summarize -> resolve -> graph -> facts."""

from __future__ import annotations

from dataclasses import dataclass, field

from authgraph.cache.summaries import SummaryCache, cache_key, default_cache, load
from authgraph.facts.models import Coverage, FactGraph, Verdict
from authgraph.frameworks.fastapi import FastAPIGraph
from authgraph.guards.config import CONFIG_FILE, Config, parse_config
from authgraph.lang.python.resolver import ProjectIndex
from authgraph.lang.python.summarizer import module_name_for, summarize
from authgraph.lang.python.summary import FileSummary
from authgraph.workspace.tree import MAX_FILE_BYTES, SourceTree, matches_any


@dataclass
class Analysis:
    facts: FactGraph
    index: ProjectIndex
    config: Config
    summaries: dict[str, FileSummary] = field(default_factory=dict)


def read_config(tree: SourceTree) -> Config:
    return parse_config(tree.read(CONFIG_FILE) if tree.exists(CONFIG_FILE) else None)


def summarize_tree(
    tree: SourceTree, cache: SummaryCache, exclude: list[str] | None = None
) -> tuple[dict[str, FileSummary], Coverage]:
    cov = Coverage()
    out: dict[str, FileSummary] = {}
    for path in tree.paths():
        if not path.endswith(".py") or (exclude and matches_any(path, exclude)):
            continue
        cov.files_total += 1
        sha = tree.blob_sha(path)
        key = cache_key("python", sha)
        s = load(cache, key)
        if s is not None:
            cov.cache_hits += 1
            # Same blob at another path (moved file): only path-derived fields change.
            module, is_pkg = module_name_for(path)
            s = s.model_copy(update={"path": path, "module": module, "is_package": is_pkg})
        else:
            data = tree.read(path)
            if len(data) > MAX_FILE_BYTES:
                cov.parse_errors.append(f"{path}: skipped (too large)")
                continue
            s = summarize(path, data, sha)
            cache.set(key, s.model_dump_json())
        if s.parse_error:
            cov.parse_errors.append(f"{path}: {s.parse_error}")
        else:
            cov.files_parsed += 1
        out[path] = s
    return out, cov


def analyze(
    tree: SourceTree, config: Config | None = None, cache: SummaryCache | None = None
) -> Analysis:
    """Build the ``FactGraph`` for one commit. ``config`` should come from the BASE branch."""
    config = config if config is not None else read_config(tree)
    summaries, cov = summarize_tree(tree, cache or default_cache(), config.paths.exclude)
    index = ProjectIndex(summaries)
    graph = FastAPIGraph(index, config)
    endpoints = graph.endpoints()
    cov.endpoints = len(endpoints)
    cov.unknown = sum(e.authn == Verdict.UNKNOWN for e in endpoints)
    cov.unresolved_imports = index.unresolved_imports
    registry = {g.symbol: g for e in endpoints for g in e.guards}
    facts = FactGraph(
        commit_sha=tree.commit_sha,
        endpoints=endpoints,
        guard_registry=sorted(registry.values(), key=lambda g: g.symbol),
        coverage=cov,
        config_public_routes=[r.route for r in config.public_routes],
        config_auth_guards=[g.symbol for g in config.auth_guards],
    )
    return Analysis(facts, index, config, summaries)
