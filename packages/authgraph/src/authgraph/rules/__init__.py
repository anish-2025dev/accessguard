"""Rule registry (PLAN.md §6.5). Order is the order findings are reported in."""

from authgraph.rules.auth import GuardRegression, MountedWithoutAuth, NewUnauthenticatedEndpoint
from authgraph.rules.base import Rule, RuleContext
from authgraph.rules.config import ConfigWidened
from authgraph.rules.consistency import RoleConsistency
from authgraph.rules.role import MassAssignment

ALL_RULES: list[Rule] = [
    GuardRegression(),
    NewUnauthenticatedEndpoint(),
    MountedWithoutAuth(),
    RoleConsistency(),
    MassAssignment(),
    ConfigWidened(),
]

__all__ = ["ALL_RULES", "Rule", "RuleContext"]
