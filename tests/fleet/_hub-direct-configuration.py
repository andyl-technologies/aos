"""Project actual SQL bootstrap and reviewed provider inputs into Worker bindings.

This module copies authority, credential and issuer identities from the genuine
operator export. Provider closure and private policy are separately supplied
observations. Producing configuration grants no runtime acceptance.
"""

import copy
import hashlib
import ipaddress
import re


PROVIDER_CONTRACT_FIELDS = {
    "contract_id", "evidence_digest", "private_completed_stage",
    "completed_upload_id_rejects_late_parts", "multipart_abort_closes_upload_id",
    "multipart_copy_from_immutable_source", "upload_part_checksum_enforced",
}


def issuer_service_binding(native_address, port, trusted_certificate, certificate_host):
    """Route to the Native VM's metadata issuer with its actual TLS verifier."""
    address = ipaddress.IPv4Address(native_address)
    if not address.is_private or address.is_loopback:
        raise ValueError("issuer requires the observed private Native VM address")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("issuer listener port is invalid")
    if not trusted_certificate.startswith("-----BEGIN CERTIFICATE-----"):
        raise ValueError("issuer requires an explicit observed certificate authority")
    if not isinstance(certificate_host, str) or not certificate_host:
        raise ValueError("issuer requires the hostname checked against its installed leaf")
    return {
        "external": {
            "address": f"{address}:{port}",
            # The pinned Miniflare union tries optional HTTP first. An explicit
            # null rejects that branch and preserves verified HTTPS settings.
            "http": None,
            "https": {
                "certificateHost": certificate_host,
                "tlsOptions": {
                    "trustBrowserCas": False,
                    "trustedCertificates": [trusted_certificate],
                },
            },
        },
    }


def external_consumer_configuration(bootstrap, provider_contract, provider_report_bytes,
                                    private_stage_policy, checksum_algorithm,
                                    maximum_grant_lifetime):
    """Bind a bootstrap projection to the exact selected provider report bytes."""
    if bootstrap["version"] != 1:
        raise ValueError("unsupported authority bootstrap version")
    if set(provider_contract) != PROVIDER_CONTRACT_FIELDS:
        raise ValueError("provider contract differs from the closed Worker schema")
    if not provider_contract["contract_id"].startswith("emulated-"):
        raise ValueError("the fleet requires an explicitly emulated provider contract")
    report_digest = hashlib.sha256(provider_report_bytes).hexdigest()
    if provider_contract["evidence_digest"] != report_digest:
        raise ValueError("selected provider observations differ from the contract")
    for field in PROVIDER_CONTRACT_FIELDS - {"contract_id", "evidence_digest"}:
        if type(provider_contract[field]) is not bool:
            raise ValueError("provider contract observation has an invalid type")
    if set(private_stage_policy) != {"policyId", "policyDigest", "namespace"}:
        raise ValueError("private stage policy differs from the typed Worker schema")
    if not re.fullmatch(r"[0-9a-f]{64}", private_stage_policy["policyDigest"]):
        raise ValueError("private stage policy commitment is invalid")
    if checksum_algorithm not in {"md5", "sha256"}:
        raise ValueError("unsupported observed provider checksum contract")
    if type(maximum_grant_lifetime) is not int or not 1 <= maximum_grant_lifetime <= 3600:
        raise ValueError("delegation policy exceeds the production bound")

    publication = bootstrap["publication"]
    installation = bootstrap["issuer_installation"]
    selector = bootstrap["selector"]
    staging_prefix = bootstrap["staging_prefix"]
    components = staging_prefix.split("/")
    if (
        ".aos-direct-qualification" not in components
        or components[-1] != ".aos-direct-upload"
        or any(component in {"", ".", ".."} for component in components)
    ):
        raise ValueError("qualification staging prefix is not explicitly confined")

    object_consumer = {
        "version": 1,
        "guard_namespace_id": publication["authority"]["guard_namespace_id"],
        "executor_identity": installation["executor_identity"],
        "issuer_key_id": bootstrap["issuer_key_id"],
        "issuer_public_key": bootstrap["issuer_public_key"],
        "timing_profile": bootstrap["timing_profile"],
        "clock_uncertainty": bootstrap["clock_uncertainty"],
        "aliases": publication["aliases"],
        "cohorts": [bootstrap["write_cohort"], bootstrap["read_cohort"]],
        "publications": [publication],
    }
    stage_domain = {
        "issuer_installation": installation,
        "publication": publication,
        "write_cohort": bootstrap["write_cohort"],
        "read_cohort": bootstrap["read_cohort"],
        "write_credential": selector["writeCredential"],
        "read_credential": selector["readCredential"],
        "presign_credential": selector["presignCredential"],
        "private_stage_policy": private_stage_policy,
        "staging_prefix": staging_prefix,
        "checksum_algorithm": checksum_algorithm,
        "maximum_grant_lifetime": str(maximum_grant_lifetime),
        "provider_contract": provider_contract,
    }
    # Preserve the exported typed values without giving later caller mutations
    # a way to change the selected original configuration.
    return copy.deepcopy({
        "HUB_EXTERNAL_OBJECT_CONSUMER": object_consumer,
        "HUB_EXTERNAL_STAGING_CONSUMER": {"version": 1, "domains": [stage_domain]},
    })
