"""Indexes immutable native TE rule candidates without replacing SETools matching.

The index preserves each original rule object, iteration order, multiplicity,
and conditional branch. Only necessary rule-type/class/permission predicates
select candidates; symbol expansion, wildcards, and all other criteria still
use the pinned SETools matcher. This is offline artifact analysis, not a live
policy or authority proof.
"""

from collections import defaultdict
from typing import Any, Iterable


class _CandidatePolicy:
    """Borrows one policy, replacing only the query's TE rule iterator."""

    def __init__(self, policy: Any, rules: Iterable[Any]) -> None:
        self._policy = policy
        self._rules = rules

    def terules(self) -> Iterable[Any]:
        return iter(self._rules)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._policy, name)

    def __str__(self) -> str:
        return str(self._policy)


class IndexedPolicyQueries:
    """Supplies the checker's one-shot queries over immutable rule candidates.

    The SETools 4.7.1 PolicyQuery.policy setter accepts a borrowed policy view.
    Each real TERuleQuery is first constructed against the original policy, so
    its criteria retain the original lookup and permission validation. Its
    unchanged results() method then reads the candidate iterator. Other query
    APIs and unsupported TE query shapes use the original implementation.

    Returned queries must keep their construction criteria unchanged, as all
    current checker helpers do. Construct a fresh query instead of mutating
    its rule type, class or permissions after a bucket has been selected.
    This is not a general replacement for mutable SETools query objects.
    """

    def __init__(self, setools: Any, policy: Any) -> None:
        self._setools = setools
        self._policy = policy
        self._allows: dict[tuple[Any, str], list[Any]] = defaultdict(list)
        self._transitions: dict[Any, list[Any]] = defaultdict(list)

        # terules() includes unconditional, filename, and both conditional
        # branches. Do not expand attributes, test enabled(), or deduplicate.
        for rule in policy.terules():
            if rule.ruletype == setools.TERuletype.allow:
                for permission in rule.perms:
                    self._allows[(rule.tclass, permission)].append(rule)
            elif rule.ruletype == setools.TERuletype.type_transition:
                self._transitions[rule.tclass].append(rule)

    def TERuleQuery(self, policy: Any, **criteria: Any) -> Any:
        """Constructs the real validated query, narrowing only its rule stream."""

        query = self._setools.TERuleQuery(policy, **criteria)
        if policy is not self._policy:
            return query

        candidates = self._candidates(query)
        if candidates is not None:
            query.policy = _CandidatePolicy(policy, candidates)
        return query

    def _candidates(self, query: Any) -> list[Any] | None:
        """Returns a necessary-predicate bucket or leaves the stock scan intact."""

        if (
            query.tclass_regex
            or not query.tclass
            or len(query.tclass) != 1
            or not query.ruletype
            or len(query.ruletype) != 1
        ):
            return None

        object_class = next(iter(query.tclass))
        rule_type = next(iter(query.ruletype))
        if rule_type == self._setools.TERuletype.allow:
            if query.perms_regex or not query.perms or len(query.perms) != 1:
                return None
            permission = next(iter(query.perms))
            return self._allows.get((object_class, permission), [])

        if rule_type == self._setools.TERuletype.type_transition and not query.perms:
            return self._transitions.get(object_class, [])

        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._setools, name)
