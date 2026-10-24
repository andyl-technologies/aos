//! Narrows installed cold-decoder limits to the actual authenticated archive.
//!
//! Every field is intersected independently. A caller-selected lower archive
//! bound therefore remains effective even when the factory was installed with
//! a larger bound; no configured ceiling is substituted for an actual demand.

use super::super::*;
use crucible_engine::{node_contract::NativeCaptureLimits, node_state::StateLimits};

pub(super) fn effective_archive_limits(
    installed: NativeArchiveLimits,
    actual: NativeArchiveLimits,
) -> NativeArchiveLimits {
    NativeArchiveLimits {
        state: StateLimits {
            maximum_record_bytes: installed
                .state
                .maximum_record_bytes
                .min(actual.state.maximum_record_bytes),
            maximum_owners_or_domains: installed
                .state
                .maximum_owners_or_domains
                .min(actual.state.maximum_owners_or_domains),
            maximum_content_bytes: installed
                .state
                .maximum_content_bytes
                .min(actual.state.maximum_content_bytes),
            maximum_total_content_bytes: installed
                .state
                .maximum_total_content_bytes
                .min(actual.state.maximum_total_content_bytes),
            maximum_content_objects: installed
                .state
                .maximum_content_objects
                .min(actual.state.maximum_content_objects),
            maximum_dependency_edges: installed
                .state
                .maximum_dependency_edges
                .min(actual.state.maximum_dependency_edges),
            maximum_dependency_depth: installed
                .state
                .maximum_dependency_depth
                .min(actual.state.maximum_dependency_depth),
            maximum_native_memory_bytes: installed
                .state
                .maximum_native_memory_bytes
                .min(actual.state.maximum_native_memory_bytes),
            maximum_native_writable_bytes: installed
                .state
                .maximum_native_writable_bytes
                .min(actual.state.maximum_native_writable_bytes),
            maximum_native_processes: installed
                .state
                .maximum_native_processes
                .min(actual.state.maximum_native_processes),
            maximum_native_descriptors: installed
                .state
                .maximum_native_descriptors
                .min(actual.state.maximum_native_descriptors),
        },
        native: NativeCaptureLimits {
            maximum_record_bytes: installed
                .native
                .maximum_record_bytes
                .min(actual.native.maximum_record_bytes),
            maximum_total_record_bytes: installed
                .native
                .maximum_total_record_bytes
                .min(actual.native.maximum_total_record_bytes),
            maximum_objects: installed
                .native
                .maximum_objects
                .min(actual.native.maximum_objects),
            maximum_artifact_bytes: installed
                .native
                .maximum_artifact_bytes
                .min(actual.native.maximum_artifact_bytes),
            maximum_total_artifact_bytes: installed
                .native
                .maximum_total_artifact_bytes
                .min(actual.native.maximum_total_artifact_bytes),
        },
    }
}

pub(super) fn requested_archive_maximum(limits: NativeArchiveLimits) -> Result<usize, StateError> {
    let maximum = usize::try_from(limits.state.maximum_native_memory_bytes)
        .map_err(error)?
        .min(limits.state.maximum_total_content_bytes)
        .min(limits.native.maximum_total_record_bytes)
        .min(512 * 1024 * 1024);
    if maximum == 0 {
        return Err(refused(
            "complete archive requested storage has zero credit",
        ));
    }
    Ok(maximum)
}

/// Checks all exact Host producer bodies before its canonical or typed copies.
fn authenticate_record_extent(
    length: usize,
    limits: NativeArchiveLimits,
) -> Result<(), StateError> {
    if length > limits.state.maximum_record_bytes || length > limits.native.maximum_record_bytes {
        return Err(refused("effective Host2 or Runtime7 record exceeds credit"));
    }
    Ok(())
}

pub(super) fn authenticate_host_record_extents(
    scope: &crucible_engine::node_state::CompleteOriginalArchiveValidation<'_>,
    references: [&ContentRef; 3],
    limits: NativeArchiveLimits,
) -> Result<(), StateError> {
    for reference in references {
        let bytes = scope
            .content
            .get(reference)
            .ok_or_else(|| refused("complete original Host record absent"))?;
        authenticate_record_extent(bytes.len(), limits)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_host_body_length_refuses_either_lower_record_cap_before_copy()
    -> Result<(), StateError> {
        let body = vec![0u8; 137];
        let mut limits = NativeArchiveLimits::default();
        limits.state.maximum_record_bytes = body.len();
        limits.native.maximum_record_bytes = body.len();
        authenticate_record_extent(body.len(), limits)?;
        limits.state.maximum_record_bytes -= 1;
        assert!(authenticate_record_extent(body.len(), limits).is_err());
        limits.state.maximum_record_bytes += 1;
        limits.native.maximum_record_bytes -= 1;
        assert!(authenticate_record_extent(body.len(), limits).is_err());
        limits.native.maximum_record_bytes += 2;
        authenticate_record_extent(body.len(), limits)?;
        Ok(())
    }

    #[test]
    fn actual_lower_archive_and_installed_limits_both_narrow_every_field() {
        let installed = NativeArchiveLimits {
            state: StateLimits {
                maximum_record_bytes: 11,
                maximum_owners_or_domains: 22,
                maximum_content_bytes: 33,
                maximum_total_content_bytes: 44,
                maximum_content_objects: 55,
                maximum_dependency_edges: 66,
                maximum_dependency_depth: 77,
                maximum_native_memory_bytes: 88,
                maximum_native_writable_bytes: 99,
                maximum_native_processes: 110,
                maximum_native_descriptors: 121,
            },
            native: NativeCaptureLimits {
                maximum_record_bytes: 132,
                maximum_total_record_bytes: 143,
                maximum_objects: 154,
                maximum_artifact_bytes: 165,
                maximum_total_artifact_bytes: 176,
            },
        };
        let actual = NativeArchiveLimits {
            state: StateLimits {
                maximum_record_bytes: 10,
                maximum_owners_or_domains: 23,
                maximum_content_bytes: 32,
                maximum_total_content_bytes: 45,
                maximum_content_objects: 54,
                maximum_dependency_edges: 67,
                maximum_dependency_depth: 76,
                maximum_native_memory_bytes: 89,
                maximum_native_writable_bytes: 98,
                maximum_native_processes: 111,
                maximum_native_descriptors: 120,
            },
            native: NativeCaptureLimits {
                maximum_record_bytes: 133,
                maximum_total_record_bytes: 142,
                maximum_objects: 155,
                maximum_artifact_bytes: 164,
                maximum_total_artifact_bytes: 177,
            },
        };

        let limits = effective_archive_limits(installed, actual);

        assert_eq!(limits.state.maximum_record_bytes, 10);
        assert_eq!(limits.state.maximum_owners_or_domains, 22);
        assert_eq!(limits.state.maximum_content_bytes, 32);
        assert_eq!(limits.state.maximum_total_content_bytes, 44);
        assert_eq!(limits.state.maximum_content_objects, 54);
        assert_eq!(limits.state.maximum_dependency_edges, 66);
        assert_eq!(limits.state.maximum_dependency_depth, 76);
        assert_eq!(limits.state.maximum_native_memory_bytes, 88);
        assert_eq!(limits.state.maximum_native_writable_bytes, 98);
        assert_eq!(limits.state.maximum_native_processes, 110);
        assert_eq!(limits.state.maximum_native_descriptors, 120);
        assert_eq!(limits.native.maximum_record_bytes, 132);
        assert_eq!(limits.native.maximum_total_record_bytes, 142);
        assert_eq!(limits.native.maximum_objects, 154);
        assert_eq!(limits.native.maximum_artifact_bytes, 164);
        assert_eq!(limits.native.maximum_total_artifact_bytes, 176);
    }

    #[test]
    fn exact_actual_requested_backing_fits_and_one_short_or_zero_refuses() -> Result<(), StateError>
    {
        let first = Vec::<u8>::with_capacity(137);
        let second = Vec::<u64>::with_capacity(73);
        let header = size_of::<super::super::super::super::retained::Counter>();
        let second_bytes = second.capacity() * size_of::<u64>();
        let demand = header + first.capacity() + second_bytes;
        let installed = NativeArchiveLimits::default();
        let mut actual = installed;
        actual.state.maximum_native_memory_bytes = demand as u64;

        let maximum = requested_archive_maximum(effective_archive_limits(installed, actual))?;

        assert_eq!(maximum, demand);
        assert_eq!(
            super::super::storage_sum([header, first.capacity(), second_bytes], maximum)?,
            demand
        );
        actual.state.maximum_native_memory_bytes -= 1;
        let short = requested_archive_maximum(effective_archive_limits(installed, actual))?;
        assert!(
            super::super::storage_sum([header, first.capacity(), second_bytes], short).is_err()
        );

        // The full read slot is a simultaneous term, not merely the
        // increase over the former buffer or an uncharged compiler frame.
        let scratch = PacketFixtureMeasurements::streaming_scratch_bytes();
        let with_stream = demand
            .checked_add(scratch)
            .ok_or_else(|| refused("test demand overflow"))?;
        actual.state.maximum_native_memory_bytes = with_stream as u64;
        let maximum = requested_archive_maximum(effective_archive_limits(installed, actual))?;
        assert_eq!(
            super::super::storage_sum([header, first.capacity(), second_bytes, scratch], maximum)?,
            with_stream
        );
        actual.state.maximum_native_memory_bytes -= 1;
        let short = requested_archive_maximum(effective_archive_limits(installed, actual))?;
        assert!(
            super::super::storage_sum([header, first.capacity(), second_bytes, scratch], short)
                .is_err()
        );

        actual.state.maximum_native_memory_bytes = 0;
        assert!(requested_archive_maximum(effective_archive_limits(installed, actual)).is_err());
        Ok(())
    }
}
