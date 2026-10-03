"""Compares indexed and stock SETools queries on a real small compiled policy.

Run with the AOS SETools Python path and a checkpolicy-compiled fixture:
``python3 -B rule_query_test.py policy.33``. The fixture is offline query data,
not an installed-policy or live-authority proof. No test is skipped.
"""

import argparse
from itertools import product
from pathlib import Path
import sys
import unittest

import setools

import rule_query


class _RecordedPolicy:
    """Supplies actual native records with deliberate repeated object custody."""

    def __init__(self, policy, records):
        self.policy = policy
        self.records = records
        self.scans = 0

    def terules(self):
        self.scans += 1
        return iter(self.records)

    def __getattr__(self, name):
        return getattr(self.policy, name)

    def __str__(self):
        return str(self.policy)


class NativeRuleQueryTest(unittest.TestCase):
    """Checks the actual pinned matcher, validation, ordering and branches."""

    policy_path: Path

    @classmethod
    def setUpClass(cls):
        cls.policy = setools.SELinuxPolicy(str(cls.policy_path))
        cls.fixture_rule_count = sum(1 for _ in cls.policy.terules())
        if cls.fixture_rule_count != 13:
            raise ValueError("differential tests require the small 13-rule compiled fixture")
        cls.comparisons = 0
        cls.index = rule_query.IndexedPolicyQueries(setools, cls.policy)

    def assert_same_results(self, **criteria):
        type(self).comparisons += 1
        stock = list(setools.TERuleQuery(self.policy, **criteria).results())
        query = self.index.TERuleQuery(self.policy, **criteria)
        indexed = list(query.results())

        # Native statements include conditional expression/block and filename;
        # a list comparison preserves ordering and repeated witnesses.
        self.assertEqual(
            [str(rule) for rule in indexed], [str(rule) for rule in stock],
        )
        self.assertEqual(
            [rule.enabled() for rule in indexed], [rule.enabled() for rule in stock],
        )
        self.assertTrue(all(rule.policy is self.policy for rule in indexed))
        return indexed

    def test_allow_symbols_attributes_indirection_and_wildcards(self):
        subjects = (None, "first_t", "second_t", "subjects")
        targets = (None, "data_t", "other_t", "targets")
        permissions = {
            "file": ("getattr", "open", "read", "write", "ioctl"),
            "fd": ("use",),
            "process": ("transition", "ptrace"),
        }
        for object_class, values in permissions.items():
            for source, target, permission, source_indirect, target_indirect in product(
                subjects, targets, values, (False, True), (False, True),
            ):
                criteria = dict(
                    ruletype=["allow"], source=source, target=target,
                    source_indirect=source_indirect, target_indirect=target_indirect,
                    tclass=[object_class], perms=[permission],
                )
                with self.subTest(**criteria):
                    self.assert_same_results(**criteria)

    def test_disabled_true_and_enabled_false_branches_remain_visible(self):
        reads = self.assert_same_results(
            ruletype=["allow"], tclass=["file"], perms=["read"],
        )
        self.assertTrue(any(not rule.enabled() for rule in reads))
        self.assertGreaterEqual(len(reads), 3)

        writes = self.assert_same_results(
            ruletype=["allow"], tclass=["file"], perms=["write"],
        )
        self.assertEqual(len(writes), 1)
        self.assertFalse(writes[0].conditional_block)
        self.assertTrue(writes[0].enabled())

    def test_all_source_scan_keeps_disabled_both_axis_attribute_grants(self):
        rules = self.assert_same_results(
            ruletype=["allow"], target="data_t", target_indirect=True,
            tclass=["fd"], perms=["use"],
        )
        self.assertEqual(len(rules), 1)
        self.assertFalse(rules[0].enabled())
        self.assertEqual(
            {str(member) for member in rules[0].source.expand()}, {"first_t", "second_t"},
        )
        self.assertEqual(
            {str(member) for member in rules[0].target.expand()}, {"data_t", "other_t"},
        )

    def test_transitions_defaults_attributes_wildcards_and_filename(self):
        for object_class, source, target, default in product(
            ("process", "dir", "file"),
            (None, "first_t", "second_t", "subjects"),
            (None, "data_t", "other_t", "targets"),
            (None, "result_t", "data_t", "outputs"),
        ):
            criteria = dict(
                ruletype=["type_transition"], tclass=[object_class],
                source=source, target=target, default=default,
                source_indirect=True, target_indirect=True,
            )
            with self.subTest(**criteria):
                self.assert_same_results(**criteria)

        named = self.assert_same_results(
            ruletype=["type_transition"], tclass=["file"],
            source="first_t", target="other_t",
        )
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0].filename, "named")
        conditional = self.assert_same_results(
            ruletype=["type_transition"], tclass=["process"],
        )
        self.assertEqual(len(conditional), 2)
        self.assertEqual({rule.enabled() for rule in conditional}, {False, True})

    def test_regex_boolean_and_permission_matcher_options(self):
        for extra in (
            dict(source="^first_t$", source_regex=True),
            dict(target=".*_t$", target_regex=True),
            dict(boolean=["query_enabled"]),
            dict(boolean=["query_enabled"], boolean_equal=True),
            dict(perms_equal=True),
            dict(perms_subset=True),
        ):
            with self.subTest(**extra):
                self.assert_same_results(
                    ruletype=["allow"], tclass=["file"], perms=["read"], **extra,
                )

    def test_other_query_shapes_use_unchanged_stock_scan(self):
        for criteria in (
            dict(ruletype=["allow"], tclass=["file"], perms=["read", "write"]),
            dict(ruletype=["allow"], tclass=["file", "fd"], perms=["read"]),
            dict(ruletype=["allow"], tclass="f.*", tclass_regex=True, perms=["read"]),
            dict(ruletype=["allow"], tclass=["file"], perms="r.*", perms_regex=True),
            dict(ruletype=["allow"]),
            dict(tclass=["file"], perms=["ioctl"]),
            dict(ruletype=["allowxperm"], tclass=["file"], perms=["ioctl"]),
            dict(ruletype=["allow", "allowxperm"], tclass=["file"], perms=["ioctl"]),
            dict(ruletype=["type_transition"], tclass=["file"], perms=["read"]),
        ):
            with self.subTest(**criteria):
                query = self.index.TERuleQuery(self.policy, **criteria)
                self.assertIs(query.policy, self.policy)
                self.assert_same_results(**criteria)

    def test_original_criterion_errors_are_not_hidden_by_empty_buckets(self):
        for extra in (
            dict(source="absent_t"), dict(target="absent_t"),
            dict(tclass=["absent_class"]), dict(perms=["absent_permission"]),
            dict(ruletype=["absent_rule_type"]), dict(default="absent_t"),
        ):
            criteria = dict(ruletype=["allow"], tclass=["file"], perms=["read"])
            criteria.update(extra)
            with self.subTest(**criteria):
                with self.assertRaises(Exception) as stock:
                    setools.TERuleQuery(self.policy, **criteria)
                with self.assertRaises(type(stock.exception)) as indexed:
                    self.index.TERuleQuery(self.policy, **criteria)
                self.assertEqual(str(indexed.exception), str(stock.exception))

    def test_snapshot_preserves_native_identity_order_and_multiplicity(self):
        records = tuple(self.policy.terules())
        repeated = next(
            rule for rule in records if rule.ruletype == setools.TERuletype.allow
        )
        policy = _RecordedPolicy(self.policy, (repeated, repeated, *records))
        index = rule_query.IndexedPolicyQueries(setools, policy)
        self.assertEqual(policy.scans, 1)
        criteria = dict(
            ruletype=["allow"], tclass=[str(repeated.tclass)],
            perms=[next(iter(repeated.perms))],
        )
        actual = list(index.TERuleQuery(policy, **criteria).results())
        self.assertEqual(policy.scans, 1)

        expected = list(setools.TERuleQuery(policy, **criteria).results())
        self.assertEqual(policy.scans, 2)
        self.assertEqual(len(actual), len(expected))
        self.assertTrue(all(a is b for a, b in zip(actual, expected)))
        self.assertIs(actual[0], repeated)
        self.assertIs(actual[1], repeated)

    def test_index_is_not_reused_for_another_policy_object(self):
        other = setools.SELinuxPolicy(str(self.policy_path))
        criteria = dict(ruletype=["allow"], tclass=["file"], perms=["read"])
        query = self.index.TERuleQuery(other, **criteria)
        self.assertIs(query.policy, other)
        self.assertEqual(
            [str(rule) for rule in query.results()],
            [str(rule) for rule in setools.TERuleQuery(other, **criteria).results()],
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    NativeRuleQueryTest.policy_path = parser.parse_args().policy
    result = unittest.main(argv=[sys.argv[0]], exit=False).result
    if result.wasSuccessful():
        print(f"fixture_native_rules={NativeRuleQueryTest.fixture_rule_count}")
        print(f"stock_indexed_result_comparisons={NativeRuleQueryTest.comparisons}")
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
