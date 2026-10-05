"""Project actual accepted External prerequisites into one Mirror transport.

The projection is configuration, not authority. A separate source-built reviewer
reopens the original provider journal, verifies the installed tuple and signs the
finite functional purpose before the Worker or Native can dispatch Mirror work.
"""

import copy
import re


def external_mirror_domain(profile, bootstrap, list_export, provider_contract):
    """Keep exact current cohorts and only explicitly observed read/closure facts."""
    if (set(profile) != {"profile", "runtimeQualification"}
            or list_export["publication"] != bootstrap["publication"]
            or list_export["issuer_installation"] != bootstrap["issuer_installation"]
            or profile["profile"]["issuerInstallation"] != bootstrap["issuer_installation"]
            or profile["profile"]["readCohort"] != bootstrap["read_cohort"]
            or profile["profile"]["writeCohort"] != bootstrap["write_cohort"]):
        raise ValueError("Mirror transport changed its independently exported prerequisite")
    listing, read = list_export["list_cohort"], bootstrap["read_cohort"]
    for field in ("authority", "association", "alias", "publication_digest", "admission_digest",
                  "admission_generation", "admitted_prefix", "executor_identity"):
        if listing[field] != read[field]:
            raise ValueError("Mirror List export is not the actual current read association")
    if listing["credential"]["purpose"] != "list" or "list" not in listing["allowed_effects"]:
        raise ValueError("Mirror inventory lacks its independently admitted List purpose")
    bound = provider_contract.get("maximum_copy_read_range_bytes")
    guarded = provider_contract.get("protected_versionless")
    if (not isinstance(bound, str) or re.fullmatch(r"[1-9][0-9]*", bound) is None
            or not 8388608 <= int(bound) <= 64 * 1024 * 1024
            or not isinstance(guarded, dict)
            or set(guarded) != {"strong_conditional_range_read", "positive_multipart_complete"}
            or any(value is not True for value in guarded.values())
            or re.fullmatch(r"[0-9a-f]{64}", provider_contract.get("evidence_digest", "")) is None):
        raise ValueError("Mirror conditional read or guarded completion remains unobserved")
    mapping = {"private_incomplete_upload": "private_incomplete_upload",
        "completed_upload_rejects_late_parts": "completed_upload_rejects_late_parts",
        "checksum_enforced": "upload_part_checksum_enforced",
        "positive_empty_put_identity": "versioned_empty_put"}
    if any(provider_contract.get(source) is not True for source in mapping.values()):
        raise ValueError("Mirror closure or empty-object identity remains unobserved")
    contract = {"observation_sha256": provider_contract["evidence_digest"],
        "read_identity": {"kind": "guarded_versionless"},
        "maximum_conditional_read_bytes": bound, "strong_conditional_read": True,
        "positive_complete_identity": True,
        **{target: provider_contract[source] for target, source in mapping.items()}}
    return copy.deepcopy({"profile": profile, "list_cohort": listing,
        "issuer_installation": bootstrap["issuer_installation"], "provider_contract": contract})


def require_mirror_reserved_cohorts(domain, binding, run):
    """Require the actual selected binding and each admitted physical descendant."""
    if not isinstance(run, str) or re.fullmatch(r"[0-9a-f]{32}", run) is None:
        raise ValueError("Mirror reserved run differs")
    selected = domain["profile"]["profile"]
    association = selected["readCohort"]["association"]
    prefix = binding["spec"]["s3"]["prefix"]
    if (association["binding_stable_id"] != binding["stableId"]
            or str(association["binding_resource_version"]) != str(binding["resourceVersion"])
            or association["binding_prefix"] != prefix
            or not prefix or prefix.startswith("/")
            or any(part in {"", ".", ".."} for part in prefix.split("/"))):
        raise ValueError("Mirror reserved scope uses another current binding")
    physical = prefix + "/.aos-mirror-qualification/" + run + "/final"
    for cohort in (selected["readCohort"], selected["writeCohort"], domain["list_cohort"]):
        admitted = cohort["admitted_prefix"].rstrip("/")
        if (cohort["association"] != association
                or not admitted or not (physical == admitted or physical.startswith(admitted + "/"))):
            raise ValueError("Mirror reserved descendants were not genuinely admitted")
    return {"bindingStableId": binding["stableId"], "bindingResourceVersion": binding["resourceVersion"],
        "bindingPrefix": prefix, "reservedPhysicalRoot": physical,
        "reservedPlacementRoot": ".aos-mirror-qualification/" + run + "/final"}
