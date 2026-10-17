"""Controlled producer-output substitutions; no signed/runtime acceptance."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


def load(name, filename):
    selected = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(selected)
    selected.loader.exec_module(module)
    return module


direct = load("paired_direct", "_hub-external-oci-direct.py")
runtime_module = load("paired_runtime", "_hub-direct-runtime-profile.py")
direct.match_paired_runtime_profiles = runtime_module.match_paired_runtime_profiles


def example():
    runtime = {"qualificationDigest": "a" * 64, "maximumParallelProviderRequests": "3"}
    bootstraps, profiles, protected, domains, declared = [], [], [], [], []
    for identity, ceiling in (("7", 3), ("8", 5)):
        association = {"binding_id": identity, "binding_stable_id": "selected-" + identity,
            "binding_resource_version": "2"}
        read = {"association": association, "purpose": "read"}
        write = {"association": association, "purpose": "write"}
        issuer = {"selectedIssuer": "current"}
        bootstraps.append({"read_cohort": read, "write_cohort": write, "issuer_installation": issuer})
        profiles.append({"profile": {"readCohort": read, "writeCohort": write,
            "issuerInstallation": issuer, "selector": {"association": association}}, "runtimeQualification": runtime})
        digest = identity * 64
        protected.append({"protectedProfileDigest": digest, "association": association})
        declared.append({"producer_profile_digest": digest, "admitted_provider_requests": ceiling})
        domains.append({**declared[-1], **association})
    artifact = {"deploymentId": "selected", "publicOrigin": "https://localhost:4673",
        "sourceDigest": "b" * 64, "scriptVersion": "selected-script", "reviewerKeyId": "selected-reviewer",
        "evidence": {"runtime": runtime, "externalProfiles": profiles}}
    declaration = {"version": 1, "deployment_id": artifact["deploymentId"],
        "public_origin": artifact["publicOrigin"], "reviewer_key_id": artifact["reviewerKeyId"], "domains": declared}
    artifact_bytes, declaration_bytes = json.dumps(artifact).encode(), json.dumps(declaration).encode()
    reviewer_bytes = b"c" * 64
    output = {"version": 1, "ceiling_semantics": "installed_configuration",
        "qualification_artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "declaration_sha256": hashlib.sha256(declaration_bytes).hexdigest(),
        "reviewer_public_key_sha256": hashlib.sha256(reviewer_bytes).hexdigest(),
        "runtime_qualification_digest": runtime["qualificationDigest"], "copy_configuration_version": 2,
        "policy": {"version": 1, "deployment_id": artifact["deploymentId"],
            "source_digest": artifact["sourceDigest"], "script_version": artifact["scriptVersion"],
            "maximum_provider_requests": 3}, "domains": domains}
    return [output, artifact, artifact_bytes, declaration, declaration_bytes, reviewer_bytes,
        {"runtime": runtime, "protectedProfiles": protected}, bootstraps]


class CapacityJoinTests(unittest.TestCase):
    def test_exact_installed_ceilings_are_not_provider_peaks(self):
        args = example()
        self.assertIs(direct.require_paired_copy_capacity(*args), args[0])
        self.assertEqual([domain["admitted_provider_requests"] for domain in args[0]["domains"]], [3, 5])
        self.assertEqual(args[0]["policy"]["maximum_provider_requests"], 3)
        self.assertNotIn("measuredPeak", args[0])

    def test_original_file_output_and_policy_substitutions_refuse(self):
        for field in ("qualification_artifact_sha256", "declaration_sha256",
                "reviewer_public_key_sha256", "runtime_qualification_digest"):
            args = example()
            args[0][field] = "f" * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                direct.require_paired_copy_capacity(*args)
        for section, field, changed in (("policy", "source_digest", "f" * 64),
                ("policy", "maximum_provider_requests", 5), ("outer", "version", True),
                ("outer", "ceiling_semantics", "observed_peak"), ("outer", "accepted", True)):
            args = example()
            (args[0] if section == "outer" else args[0][section])[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                direct.require_paired_copy_capacity(*args)

    def test_domain_identity_bounds_and_current_cohort_substitutions_refuse(self):
        for field, changed in (("binding_id", "7"), ("binding_stable_id", "foreign"),
                ("binding_resource_version", "3"), ("producer_profile_digest", "f" * 64),
                ("admitted_provider_requests", 6)):
            args = example()
            args[0]["domains"][1][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                direct.require_paired_copy_capacity(*args)
        args = copy.deepcopy(example())
        args[7][1]["write_cohort"]["association"]["binding_resource_version"] = "3"
        with self.assertRaises(ValueError):
            direct.require_paired_copy_capacity(*args)


if __name__ == "__main__":
    unittest.main()
