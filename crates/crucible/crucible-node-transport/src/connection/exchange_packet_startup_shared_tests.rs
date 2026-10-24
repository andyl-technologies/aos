//! Compares the sole startup loop with its independent original implementation.

use super::*;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::startup as shared;

type Components = (usize, Option<usize>, usize, [usize; 11], [usize; 11]);

fn values(value: &OriginalSerializationStorageData) -> [usize; 11] {
    [
        value.dom_and_canonical_scratch_bytes,
        value.retained_value_backing_bytes,
        value.projected_parser_requested_bytes,
        value.canonical_output_requested_bytes,
        value.serializer_temporary_requested_bytes,
        value.declared_counter_scratch_bytes,
        value.maximum_encoded_bytes,
        value.sequence_elements,
        value.sequence_containers,
        value.serialized_value_nodes,
        value.serialized_capacity_records,
    ]
}

fn components(value: &OriginalPacketPrefixProjectionStorageData) -> Components {
    (
        value.source_owner_requested_bytes,
        value.native_source_backing_bytes,
        value.maximum_requested_bytes,
        values(&value.terminal),
        values(&value.original),
    )
}

fn input<'a>(
    original: &'a OriginalSerializationStorageData,
    terminal: &'a OriginalSerializationStorageData,
    objects: &'a [OriginalContinuationContentExtent<'a>],
    maximum: usize,
) -> OriginalPacketPrefixProjectionInput<'a> {
    OriginalPacketPrefixProjectionInput {
        original,
        terminal,
        objects,
        maximum_requested_bytes: maximum,
    }
}

#[test]
fn shared_startup_keeps_original_frames_components_and_baseline_partition() -> TestResult {
    let (_, authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let (original, terminal) = original_and_terminal(&authority)?;
    let fixed = original_packet_prefix_fixed_layout_data();
    let objects = [
        OriginalContinuationContentExtent {
            maximum_payload_bytes: 0,
            media_type: "application/json",
        },
        OriginalContinuationContentExtent {
            maximum_payload_bytes: 1025,
            media_type: "text/plain; k=\"v\"",
        },
        OriginalContinuationContentExtent {
            maximum_payload_bytes: 65_536,
            media_type: "application/json",
        },
    ];
    for (count, baseline) in [(1, false), (2, false), (3, false), (0, true), (2, true)] {
        let expected = super::super::original::quote_startup_parts_for::<3>(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            selection.provider.extensions_supported.len(),
            input(&original, &terminal, &objects[..count], MAXIMUM),
            baseline,
            PrefixClass::Observe,
        )?;
        let actual = shared::quote_original_parts(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            selection.provider.extensions_supported.len(),
            input(&original, &terminal, &objects[..count], MAXIMUM),
            baseline,
            &fixed,
            &acknowledgements::ACK_FIXED_LAYOUT,
        )?;

        assert_eq!(actual.exchange, expected.exchange);
        assert_eq!(components(&actual), components(&expected));
        assert!(actual.class == expected.class);
        assert_eq!(actual.objects.iter().flatten().count(), count);
        for (a, b) in actual.objects.iter().zip(&expected.objects) {
            assert_eq!(
                a.map(|v| (v.payload, v.media)),
                b.map(|v| (v.payload, v.media))
            );
        }
        assert_eq!(
            actual.declared_counter_scratch_bytes,
            expected.declared_counter_scratch_bytes + 3 * size_of::<usize>()
        );
        assert_eq!(
            actual.requested_bytes()?,
            expected.requested_bytes()? + 3 * size_of::<usize>()
        );
    }
    Ok(())
}

#[test]
fn shared_startup_keeps_media_population_and_exact_new_counter_cap_refusals() -> TestResult {
    let (_, authority, selection, _) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let (original, terminal) = original_and_terminal(&authority)?;
    let fixed = original_packet_prefix_fixed_layout_data();
    for (payload, media) in [(65_537, "application/json"), (1, ""), (1, "not\nprintable")] {
        let objects = [OriginalContinuationContentExtent {
            maximum_payload_bytes: payload,
            media_type: media,
        }];
        let old = super::super::original::quote_startup_parts_for::<3>(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            selection.provider.extensions_supported.len(),
            input(&original, &terminal, &objects, MAXIMUM),
            false,
            PrefixClass::Observe,
        );
        let new = shared::quote_original_parts(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            selection.provider.extensions_supported.len(),
            input(&original, &terminal, &objects, MAXIMUM),
            false,
            &fixed,
            &acknowledgements::ACK_FIXED_LAYOUT,
        );
        let old_error = old
            .err()
            .ok_or("original unexpectedly accepted invalid content")?;
        let new_error = new
            .err()
            .ok_or("shared unexpectedly accepted invalid content")?;
        assert_eq!(format!("{new_error:?}"), format!("{old_error:?}"));
    }
    let objects = [OriginalContinuationContentExtent {
        maximum_payload_bytes: 1,
        media_type: "application/json",
    }];
    let full = shared::quote_original_parts(
        (authority.session_id(), authority.incarnation_id()),
        authority.limits(),
        selection.provider.extensions_supported.len(),
        input(&original, &terminal, &objects, MAXIMUM),
        false,
        &fixed,
        &acknowledgements::ACK_FIXED_LAYOUT,
    )?
    .requested_bytes()?;
    let exact = shared::quote_original_parts(
        (authority.session_id(), authority.incarnation_id()),
        authority.limits(),
        selection.provider.extensions_supported.len(),
        input(&original, &terminal, &objects, full),
        false,
        &fixed,
        &acknowledgements::ACK_FIXED_LAYOUT,
    )?;
    assert_eq!(exact.requested_bytes()?, full);
    assert!(
        shared::quote_original_parts(
            (authority.session_id(), authority.incarnation_id()),
            authority.limits(),
            selection.provider.extensions_supported.len(),
            input(&original, &terminal, &objects, full - 1),
            false,
            &fixed,
            &acknowledgements::ACK_FIXED_LAYOUT,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn compiled_prefix_facts_match_original_private_types_and_actual_getters() {
    let fixed = original_packet_prefix_fixed_layout_data();
    assert_eq!(fixed.envelope_bytes, size_of::<Envelope>());
    assert_eq!(fixed.envelope_alignment, align_of::<Envelope>());
    assert_eq!(fixed.received_frame_bytes, size_of::<ReceivedFrame>());
    assert_eq!(fixed.exchange_record_bytes, size_of::<ExchangeRecord>());
    assert_eq!(
        fixed.response_iterator_bytes,
        size_of::<std::collections::btree_map::Values<'static, Id, Envelope>>()
    );
    assert_eq!(
        fixed.reply_bytes,
        size_of::<crate::reference_packet::control::PacketControlReply>()
    );
    assert_eq!(fixed.incident_bytes, size_of::<ConnectionIncident>());
    assert_eq!(
        fixed.body_header_bytes,
        size_of::<ResponseBody>().max(size_of::<RequestBody>())
    );
    assert_eq!(fixed.quote_counter_scratch_bytes,
        Connection::<crate::client::DeadlineStream>::original_packet_prefix_quote_scratch_bytes_data());
    assert_eq!(
        fixed.startup_counter_scratch_bytes,
        startup_counter_additional_scratch_data()
    );
    assert_eq!(
        startup_counter_additional_scratch_data_for::<3>(),
        super::super::original::startup_counter_additional_scratch_data_for::<3>()
            + 3 * size_of::<usize>()
    );
    assert_eq!(
        original_packet_prefix_fixed_layout_counter_scratch_data(),
        2 * size_of::<shared::PacketPrefixFixedLayoutData>() + 2 * size_of::<usize>()
    );
}
