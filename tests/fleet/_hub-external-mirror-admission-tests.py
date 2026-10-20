"""Controlled joins preserve actual cohort and report identities, not acceptance."""

import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("mirror_admission", Path(__file__).with_name(
    "_hub-external-mirror-admission.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def inputs():
    association = {"binding_id": "2", "binding_stable_id": "selected-binding",
        "binding_resource_version": "3", "binding_prefix": "selected/prefix"}
    common = {"authority": {"id": "controlled-authority"}, "association": association,
        "alias": {"id": "controlled-alias"}, "publication_digest": "a" * 64,
        "admission_digest": "b" * 64, "admission_generation": "4",
        "admitted_prefix": "selected/prefix", "executor_identity": "controlled-executor"}
    cohorts = {purpose: {**copy.deepcopy(common), "credential": {"purpose": purpose},
        "allowed_effects": [purpose]} for purpose in ("read", "write", "list")}
    bootstrap = {"publication": {"digest": "a" * 64},
        "issuer_installation": {"executor_identity": "controlled-executor"},
        "read_cohort": cohorts["read"], "write_cohort": cohorts["write"]}
    listing = {"version": 1, "publication": bootstrap["publication"],
        "issuer_installation": bootstrap["issuer_installation"], "list_cohort": cohorts["list"]}
    profile = {"profile": {"issuerInstallation": bootstrap["issuer_installation"],
        "readCohort": cohorts["read"], "writeCohort": cohorts["write"]},
        "runtimeQualification": {"qualificationDigest": "c" * 64}}
    contract = {"evidence_digest": "d" * 64, "maximum_copy_read_range_bytes": "8388608",
        "protected_versionless": {"strong_conditional_range_read": True, "positive_multipart_complete": True},
        "private_incomplete_upload": True, "completed_upload_rejects_late_parts": True,
        "upload_part_checksum_enforced": True, "versioned_empty_put": True}
    binding = {"stableId": "selected-binding", "resourceVersion": "3",
        "spec": {"s3": {"prefix": "selected/prefix"}}}
    return profile, bootstrap, listing, contract, binding


class MirrorAdmissionTests(unittest.TestCase):
    def test_exact_exported_profiles_and_observed_read_contract_are_preserved(self):
        profile, bootstrap, listing, contract, binding = inputs()
        domain = fixture.external_mirror_domain(profile, bootstrap, listing, contract)
        self.assertEqual(domain["profile"], profile)
        self.assertEqual(domain["list_cohort"], listing["list_cohort"])
        self.assertEqual(domain["provider_contract"]["maximum_conditional_read_bytes"], "8388608")
        self.assertEqual(domain["provider_contract"]["observation_sha256"], contract["evidence_digest"])
        selected = fixture.require_mirror_reserved_cohorts(domain, binding, "e" * 32)
        self.assertEqual(selected["reservedPhysicalRoot"],
            "selected/prefix/.aos-mirror-qualification/" + "e" * 32 + "/final")
        self.assertNotIn("accepted", selected)

    def test_unknown_range_or_closure_and_drifted_list_export_refuse(self):
        for field, value in (("maximum_copy_read_range_bytes", None),
                ("maximum_copy_read_range_bytes", "4096"),
                ("maximum_copy_read_range_bytes", "08388608"),
                ("private_incomplete_upload", False), ("versioned_empty_put", False)):
            profile, bootstrap, listing, contract, _ = inputs()
            contract[field] = value
            with self.assertRaises(ValueError):
                fixture.external_mirror_domain(profile, bootstrap, listing, contract)
        profile, bootstrap, listing, contract, _ = inputs()
        listing["list_cohort"]["association"]["binding_id"] = "other"
        with self.assertRaises(ValueError):
            fixture.external_mirror_domain(profile, bootstrap, listing, contract)

    def test_stale_binding_or_narrow_cohort_cannot_admit_reserved_mirror_children(self):
        for mutate in (lambda binding, domain: binding.update(resourceVersion="4"),
                lambda binding, domain: binding.update(stableId="different"),
                lambda binding, domain: domain["list_cohort"].update(admitted_prefix="selected/prefix/registry")):
            profile, bootstrap, listing, contract, binding = inputs()
            domain = fixture.external_mirror_domain(profile, bootstrap, listing, contract)
            mutate(binding, domain)
            with self.assertRaises(ValueError):
                fixture.require_mirror_reserved_cohorts(domain, binding, "e" * 32)


if __name__ == "__main__":
    unittest.main()
