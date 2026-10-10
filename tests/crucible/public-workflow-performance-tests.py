"""Exercise receipt validation without claiming a native performance flight."""

from pathlib import Path
import runpy
import unittest

CODE = runpy.run_path(str(Path(__file__).with_name("public-workflow-performance.py")))


def completed_output():
    return "\n".join([
        "campaign_default_run=true",
        "campaign_default_run_completed_campaigns=1",
        "campaign_default_run_process_host_ns=123456",
        "campaign_default_run_physical_quanta=2",
        "campaign_default_run_frontier_ticks=2000000",
        "campaign_default_run_measurement=shipped-cli-spawn-through-exit",
        "campaign_default_run_completion=authenticated-public-campaign",
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
    ])


class ReceiptTests(unittest.TestCase):
    def test_accepts_only_original_successful_completion(self):
        sample = CODE["parse_sample"](completed_output())
        self.assertEqual(sample["process_host_ns"], 123456)
        with self.assertRaises(ValueError):
            CODE["parse_sample"](completed_output().replace("1 passed", "0 passed"))
        with self.assertRaises(ValueError):
            CODE["parse_sample"](completed_output() + "\ncampaign_default_run=true")
        with self.assertRaises(ValueError):
            CODE["parse_sample"](completed_output().replace("physical_quanta=2", "physical_quanta=0"))

    def test_rejects_a_regression_without_relaxation(self):
        rows = [{"variant": name, "process_host_ns": duration}
                for name, duration in [("baseline", 100), ("candidate", 99),
                                       ("candidate", 101), ("baseline", 100)]]
        self.assertFalse(CODE["compare"](rows)["no_regression"])
        rows[2]["process_host_ns"] = 100
        self.assertTrue(CODE["compare"](rows)["no_regression"])

    def test_matches_independently_authored_launch_partitions(self):
        common = {"schema": "crucible.campaign-packaged-executor",
                  "maximum_slots": 1, "worker_count": 1,
                  "qemu_profile": "deterministic-tcg-v1", "maximum_tasks": 64}
        baseline = dict(common, version=2, maximum_resident_bytes=536870912,
                        maximum_disk_bytes=2147483648, maximum_vcpus=1,
                        maximum_execution_quanta=10000)
        candidate = dict(common, version=3, watcher_service_resident_bytes=1048576,
                         maximum_node_host_service_resident_bytes=8388608,
                         assignment_resources={"resident_peak_bytes": 550502400,
                                               "backing_peak_bytes": 2151694336},
                         assignment_limits={"execution_quanta": 10000})
        self.assertEqual(CODE["native_limits"](baseline), CODE["native_limits"](candidate))
        candidate["assignment_resources"]["backing_peak_bytes"] -= 1
        self.assertNotEqual(CODE["native_limits"](baseline), CODE["native_limits"](candidate))


if __name__ == "__main__":
    unittest.main()
