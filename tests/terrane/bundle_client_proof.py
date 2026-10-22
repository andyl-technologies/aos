"""Binds actual client socket reads to the SDK's private bundle completion path."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "successful_terminal_metadata_allows_registered_schema_and_requested_profile",
    "protocol_error_after_metadata_discards_objects_before_schema_validation",
    "plain_body_eof_incomplete_termination_and_transport_cutoff_never_complete",
    "whole_call_deadline_drops_pending_response_without_exposing_metadata",
    "caller_cancellation_closes_the_actual_response_stream",
    "decoder_bounds_and_metadata_refusals_return_no_partial_result",
    "missing_zero_and_unrepresentable_call_limits_refuse_before_connecting",
    "synchronous_schema_completion_after_deadline_is_refused",
    "clean_protocol_termination_accepts_all_held_empty_results",
    "aggregate_bundle_limit_refuses_after_valid_metadata_before_validation",
]


if __name__ == "__main__":
    run_sdk_contract(
        "bundle_client", CASES,
        "Actual generated-client HTTP framing, deadline and cancellation checks; "
        "private representations only, no authorized repository server claim",
    )
