"""Binds complete private fallback range reads to actual generated-client sockets."""

from sdk_contract_proof import run_sdk_contract


CASES = [
    "contiguous_absolute_offsets_and_successful_termination_return_exact_private_bytes",
    "exact_coverage_never_substitutes_for_successful_protocol_termination",
    "gaps_overlap_reordering_empty_frames_and_short_results_are_refused",
    "excess_bytes_frames_and_protocol_frame_size_are_refused",
    "empty_range_requires_successful_termination_without_data",
    "malformed_requests_and_resource_excess_refuse_before_connecting",
    "decoder_and_transport_cutoff_refuse_without_partial_bytes",
    "whole_call_deadline_closes_pending_actual_response_stream",
    "caller_cancellation_closes_actual_response_and_discards_pending_bytes",
    "unbounded_or_zero_buffer_limits_are_refused",
    "maximum_legal_frame_and_near_limit_offsets_preserve_exact_coverage",
]


if __name__ == "__main__":
    run_sdk_contract(
        "range_client", CASES,
        "Actual protocol framing, exact coverage, deadline and cancellation checks; "
        "unverified private bytes only, no admission or authorized server claim",
    )
