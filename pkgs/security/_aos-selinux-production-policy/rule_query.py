"""Indexes immutable native TE rule candidates without replacing SETools matching.

The index preserves each original rule object, iteration order, multiplicity,
and conditional branch. Necessary rule-type/class/permission and literal-type
predicates select candidates; the pinned SETools matcher still applies every
criterion. This is offline artifact analysis, not a live policy or authority
proof.
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
    its rule type, class, permissions, source or target after selection.
    This is not a general replacement for mutable SETools query objects.
    """

    def __init__(self, setools: Any, policy: Any) -> None:
        self._setools = setools
        self._policy = policy
        self._allows: dict[tuple[Any, str], list[Any]] = defaultdict(list)
        self._extended_allows: dict[Any, list[Any]] = defaultdict(list)
        self._transitions: dict[Any, list[Any]] = defaultdict(list)
        self._empty: list[Any] = []
        self._members: dict[Any, frozenset[Any]] = {}
        self._literal_buckets: dict[tuple[Any, ...], list[Any]] = {}

        # terules() includes unconditional, filename, and both conditional
        # branches. Do not expand attributes, test enabled(), or deduplicate.
        for rule in policy.terules():
            if rule.ruletype == setools.TERuletype.allow:
                for permission in rule.perms:
                    self._allows[(rule.tclass, permission)].append(rule)
            elif rule.ruletype == setools.TERuletype.allowxperm:
                self._extended_allows[rule.tclass].append(rule)
            elif rule.ruletype == setools.TERuletype.type_transition:
                self._transitions[rule.tclass].append(rule)

    def TERuleQuery(self, policy: Any, **criteria: Any) -> Any:
        """Constructs the real validated query, narrowing only its rule stream."""

        query = self._setools.TERuleQuery(policy, **criteria)
        if policy is not self._policy:
            return query

        candidates = self._candidates(query)
        if candidates is not None:
            candidates = self._literal_candidates(query, candidates)
            query.policy = _CandidatePolicy(policy, candidates)
        return query

    def _literal_candidates(self, query: Any, candidates: list[Any]) -> list[Any]:
        """Retains literal-type witnesses, including indirect attribute grants."""

        for axis in ("source", "target"):
            symbol = getattr(query, axis)
            if getattr(query, f"{axis}_regex") or not isinstance(symbol, self._setools.Type):
                continue

            indirect = getattr(query, f"{axis}_indirect")
            # Every input list remains owned by the immutable index or this
            # cache, so its identity cannot be recycled during the index life.
            key = (id(candidates), axis, symbol, indirect)
            narrowed = self._literal_buckets.get(key)
            if narrowed is None:
                narrowed = [
                    rule for rule in candidates
                    if self._contains_type(getattr(rule, axis), symbol, indirect)
                ]
                self._literal_buckets[key] = narrowed
            candidates = narrowed

        return candidates

    def _contains_type(self, rule_symbol: Any, symbol: Any, indirect: bool) -> bool:
        """Applies only the pinned matcher's necessary literal-type predicate."""

        if not indirect:
            return rule_symbol == symbol

        # A Type expands to itself. Attribute criteria and regexes deliberately
        # stay with SETools; rule-side attributes must retain all their members,
        # including those in disabled conditional branches.
        members = self._members.get(rule_symbol)
        if members is None:
            members = frozenset(rule_symbol.expand())
            self._members[rule_symbol] = members
        return symbol in members

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
            return self._allows.get((object_class, permission), self._empty)

        if rule_type == self._setools.TERuletype.type_transition and not query.perms:
            return self._transitions.get(object_class, self._empty)

        if rule_type == self._setools.TERuletype.allowxperm:
            # Numeric selector ranges and permission options still belong to
            # SETools. Only rule type, class and literal symbols narrow here.
            return self._extended_allows.get(object_class, self._empty)

        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._setools, name)
