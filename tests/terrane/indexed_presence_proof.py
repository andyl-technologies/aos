"""Binds committed index membership to actual native publication and body controls."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "committed_presence_preserves_hash_order_duplicates_and_metadata_across_reopen",
    "virtual_empty_chunk_without_committed_entry_is_not_index_presence",
    "empty_and_excessive_requests_are_decided_before_any_backend_io",
    "maximum_batch_uses_committed_entries_and_quarantine_removes_presence",
    "committed_index_presence_does_not_substitute_for_body_verification",
    "malformed_selected_index_returns_no_partial_membership",
    "durable_container_inventory_does_not_admit_its_members_to_index_presence",
]


if __name__ == "__main__":
    run_sdk_contract(
        "indexed_presence", CASES,
        "Actual file-bucket committed-index observations; independently verified "
        "body reads remain required and no protocol authorization is claimed",
    )
