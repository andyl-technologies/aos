"""Checks the isolated ordinary configuration without starting workerd."""

import importlib.util
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("worker_smoke", HERE / "hub-worker-only.py")
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class WorkerConfigurationTests(unittest.TestCase):
    def test_ordinary_shards_and_persistence_are_explicit(self):
        configuration = SMOKE.worker_configuration(Path("/fixture/dist"), Path("/fixture/state"), 8443, "seal")
        self.assertEqual(configuration["bindings"]["HUB_TOPOLOGY"], "worker_only")
        self.assertEqual(configuration["bindings"]["HUB_REQUEST_SHARDING"], "on")
        self.assertEqual(configuration["bindings"]["HUB_EXTERNAL_URL"], "https://localhost:8443")
        self.assertTrue(configuration["durableObjects"]["HUB_DB"]["useSQLite"])
        self.assertEqual(len(configuration["durableObjects"]), 6)
        for resource in ["durableObjectsPersist", "kvPersist", "r2Persist"]:
            self.assertTrue(configuration[resource])
        self.assertNotIn("acceptanceSocketPath", configuration)
        self.assertNotIn("HYBRID_OBJECT_GUARD", configuration["durableObjects"])

    def test_client_reuses_existing_password_and_reviewed_api_implementation(self):
        self.assertIs(SMOKE.WorkerHub.login, SMOKE.SETTINGS.NativeHub.login)
        self.assertIs(SMOKE.WorkerHub.reviewed, SMOKE.SETTINGS.NativeHub.reviewed)
        self.assertIs(SMOKE.WorkerHub.rpc, SMOKE.SETTINGS.NativeHub.rpc)


if __name__ == "__main__":
    unittest.main()
