"""Covers recycled sequential namespace IDs and real simultaneous sharing."""

from copy import deepcopy
import unittest

from verify_worktree_cache import validate_metrics


class WorktreeTopologyTests(unittest.TestCase):
    def fixture(self):
        return {
            role: {
                "started_unix_ns": start, "finished_unix_ns": start + 10,
                "output_base_inode": 7, "server_before": None,
                "disk_cache": None if role == "uncached" else "/cache/trial",
                "namespaces": {name: name + ":[123]" for name in ["mnt", "net", "pid", "user"]},
            }
            for role, start in [("producer", 1), ("consumer", 20), ("uncached", 40)]
        }

    def overlapping(self):
        metrics = self.fixture()
        metrics["uncached"].update(started_unix_ns=5, finished_unix_ns=9, output_base_inode=8)
        metrics["uncached"]["namespaces"] = {
            name: name + ":[456]" for name in ["mnt", "net", "pid", "user"]
        }
        return metrics

    def test_serial_namespace_and_directory_inode_reuse_is_not_sharing(self):
        result = validate_metrics(self.fixture())
        self.assertEqual(result["overlapping_pairs"], [])

    def test_distinct_overlapping_builds_are_accepted(self):
        result = validate_metrics(self.overlapping())
        self.assertEqual(result["overlapping_pairs"], [{"roles": ["producer", "uncached"], "overlap_ns": 4}])

    def test_overlap_requires_live_namespace_and_directory_separation(self):
        for field in ["mnt", "net", "pid", "user", "output_base_inode"]:
            metrics = self.overlapping()
            if field == "output_base_inode":
                metrics["uncached"][field] = metrics["producer"][field]
            else:
                metrics["uncached"]["namespaces"][field] = metrics["producer"]["namespaces"][field]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "overlapping"):
                validate_metrics(metrics)

    def test_cache_configuration_and_servers_are_checked(self):
        changes = [
            ("consumer", "disk_cache", "/other/cache"),
            ("uncached", "disk_cache", "/cache/trial"),
            ("producer", "server_before", 42),
        ]
        for role, field, value in changes:
            metrics = self.fixture()
            metrics[role][field] = value
            with self.subTest(field=field, role=role), self.assertRaises(ValueError):
                validate_metrics(metrics)

    def test_missing_invalid_times_and_producer_order_are_rejected(self):
        original = self.fixture()
        for field, value in [("started_unix_ns", 0), ("finished_unix_ns", 1),
                             ("started_unix_ns", True), ("output_base_inode", -1)]:
            metrics = deepcopy(original)
            metrics["producer"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_metrics(metrics)

        original["consumer"]["started_unix_ns"] = 5
        with self.assertRaisesRegex(ValueError, "before the producer"):
            validate_metrics(original)
        with self.assertRaisesRegex(ValueError, "requires producer"):
            validate_metrics({})


if __name__ == "__main__":
    unittest.main()
