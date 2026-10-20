//! Counts the actual new purpose owners beside the unchanged baseline quote.
//!
//! Four Source-purpose trees survive in bootstrap bootValue, NativeAckBoot data
//! and its association/policy normalizations. The independent launchValue holds
//! the fifth purpose tree. Each named closed projection conservatively retains
//! canonical work too, following the existing baseline producer's contract.
//! Source finalization/wire ownership is priced separately from native rows.
//! Enlarged allocation rows are counted at their full quoted-U64 width before
//! their actual values are known. Fixed typed launch wrappers are separate from
//! these Value trees, including a conservative retained and second-decode view.

use super::wire::original_native_invocation_launch_identity_data;
use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_json_value_storage_extent_data,
};

/// Separates the additional owners of the new strict private invocation edition.
///
/// The unchanged baseline remains mandatory. This DATA cannot issue a grant,
/// replace that baseline or relax any original absolute bank/frame ceiling.
pub struct PacketNativeInvocationConstructionStorageData {
    native_retained: usize,
    native_transient: usize,
    private_retained: usize,
    private_transient: usize,
    source_finalization: usize,
    wire_growth: usize,
    maximum_boot: usize,
    launch: super::wire::PacketNativeInvocationLaunchIdentityData,
}

impl PacketNativeInvocationConstructionStorageData {
    /// Returns the additional persistent native owners.
    pub const fn native_retained_requested_bytes(&self) -> usize {
        self.native_retained
    }
    /// Returns the additional simultaneous native construction phase.
    pub const fn native_transient_requested_bytes(&self) -> usize {
        self.native_transient
    }
    /// Returns the additional persistent private bootstrap owners.
    pub const fn private_retained_requested_bytes(&self) -> usize {
        self.private_retained
    }
    /// Returns the additional simultaneous private parsing/construction phase.
    pub const fn private_transient_requested_bytes(&self) -> usize {
        self.private_transient
    }
    /// Returns Source-owned finalization/writer owner and work credit.
    pub const fn source_finalization_requested_bytes(&self) -> usize {
        self.source_finalization
    }
    /// Returns the additional separately retained Source wire-bank capacity.
    pub const fn wire_growth_requested_bytes(&self) -> usize {
        self.wire_growth
    }
    /// Returns the new closed boot-frame bound under the original 512 KiB ceiling.
    pub const fn maximum_private_boot_body_bytes(&self) -> usize {
        self.maximum_boot
    }
    /// Copies the exact streamed launch6 identity, including the unchanged launch5 bank.
    pub const fn launch_identity_data(
        &self,
    ) -> super::wire::PacketNativeInvocationLaunchIdentityData {
        self.launch
    }
}

fn total(parts: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    parts.iter().try_fold(0usize, |sum, n| {
        sum.checked_add(*n)
            .filter(|n| *n <= maximum)
            .ok_or_else(invalid)
    })
}

fn field(
    purpose: &PacketNativeInvocationPurposeData,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    p.add_object()?;
    p.add_field("invocation")?;
    p.add_value(purpose)?;
    p.finish(maximum)
}

fn wrapper(
    purpose: &PacketNativeInvocationPurposeData,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    p.add_object()?;
    p.add_field("schema_version")?;
    p.add_value(&6u16)?;
    p.add_field("invocation")?;
    p.add_value(purpose)?;
    // Existing full launch5 ownership is charged by the baseline. This extra
    // null charges its new wrapper value slot without replacing that owner.
    p.add_field("launch")?;
    p.add_value(&())?;
    p.finish(maximum)
}

// The old baseline serialized its actual row values. Enlarging those rows can
// increase every quoted decimal, so count the entire replacement field with all
// three rows at their full U64 width. This also dominates the nullable None case
// without borrowing spare credit from an unrelated purpose tree.
fn allocation_rows(maximum: usize) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    p.add_object()?;
    p.add_field("native_startup_allocation")?;
    p.add_object()?;
    p.add_field("schema")?;
    p.add_string(super::super::PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA)?;
    for name in ["private_bootstrap", "native_birth", "restore_prepare"] {
        p.add_field(name)?;
        p.add_object()?;
        for field in [
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ] {
            p.add_field(field)?;
            p.add_unescaped_ascii_extent(20)?;
        }
    }
    p.finish(maximum)
}

/// Quotes the actual new owners around an authenticated legacy launch literal.
///
/// The baseline quote supplies its real old private boot bound. JSON occurrence
/// and compiled Value/String/Vec/tree layouts produce the changed raw parser
/// phase; encoded byte counts are never used directly as a heap conversion.
/// Old baseline rows remain intact and the actual action must admit both.
///
/// # Errors
/// Refuses checked overflow, changed absolute frame ceilings, incomplete closed
/// serialization or a requested component exceeding the caller's data ceiling.
pub fn original_native_invocation_construction_storage_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5: &[u8],
    old_maximum_boot_bytes: usize,
    maximum: usize,
) -> Result<PacketNativeInvocationConstructionStorageData, ProviderError> {
    let field = field(purpose, maximum)?;
    let wrapper = wrapper(purpose, maximum)?;
    let rows = allocation_rows(maximum)?;
    let launch = original_native_invocation_launch_identity_data(purpose, canonical_launch5)?;
    let encoded_growth = launch
        .encoded_bytes
        .checked_sub(canonical_launch5.len())
        .ok_or_else(invalid)?;
    let maximum_boot = total(
        &[
            old_maximum_boot_bytes,
            field.maximum_encoded_bytes,
            rows.maximum_encoded_bytes,
        ],
        maximum,
    )?;
    if maximum_boot > 512 * 1024 || launch.encoded_bytes > 1024 * 1024 {
        return Err(invalid());
    }
    let old_parser = original_json_value_storage_extent_data(
        canonical_launch5.len().max(old_maximum_boot_bytes),
    )?;
    let new_parser =
        original_json_value_storage_extent_data(launch.encoded_bytes.max(maximum_boot))?;
    let parser_growth = new_parser
        .canonical_pass_requested_bytes()?
        .checked_sub(old_parser.canonical_pass_requested_bytes()?)
        .ok_or_else(invalid)?;
    let purpose_tree = field.requested_total()?;
    let wrapper_tree = wrapper.requested_total()?;
    let row_tree = rows.requested_total()?;
    let source_tree = total(&[purpose_tree, row_tree], maximum)?;
    let typed_wrapper = std::mem::size_of::<super::super::PacketNative6InvocationLaunch>();
    let native_retained = total(
        &[
            source_tree,                // bootstrap bootValue.source_birth
            source_tree,                // NativeAckBoot.data.source_birth
            source_tree,                // normalized association.source_binding
            source_tree,                // normalized policy.source_binding
            wrapper_tree,               // original independent launchValue wrapper
            encoded_growth,             // NativeAckBoot retained original launch_body
            rows.maximum_encoded_bytes, // independently retained canonical Source body
            typed_wrapper,              // conservative independent first typed launch6 owner
        ],
        maximum,
    )?;
    let private_retained = total(
        &[
            wrapper_tree,   // retained private launchValue wrapper
            source_tree,    // retained private bootValue Source child
            encoded_growth, // private launch_bytes bank
            typed_wrapper,  // conservative independent first typed launch6 owner
        ],
        maximum,
    )?;
    let native_transient = total(
        &[
            source_tree,   // independently constructed expected Source binding
            wrapper_tree,  // later independent Value launch decode and validation
            typed_wrapper, // second typed decode while the first may remain retained
            std::mem::size_of::<PacketNativeInvocationPurposeData>(),
        ],
        maximum,
    )?;
    let private_transient = total(
        &[
            parser_growth,
            wrapper_tree,
            source_tree,
            typed_wrapper, // second typed conversion beside the retained first owner
            std::mem::size_of::<PacketNativeInvocationPurposeData>(),
        ],
        maximum,
    )?;
    let source_finalization = total(
        &[
            purpose_tree,               // new invocation Value moved into the retained full body
            purpose_tree,               // independent invocation addition/encoding work
            row_tree,                   // enlarged NativeAdditions allocation child
            row_tree,                   // independent finalizer parsed Source allocation child
            row_tree,                   // independent wire boot-frame Source allocation clone
            rows.maximum_encoded_bytes, // finalizer replacement raw encoding work
            rows.maximum_encoded_bytes, // independent wire boot-frame raw encoding work
            wrapper_tree,               // Source wrapper encoding and closed wire preparation work
            encoded_growth,             // separately retained wrapper bank in Source wire holder
        ],
        maximum,
    )?;
    Ok(PacketNativeInvocationConstructionStorageData {
        native_retained,
        native_transient,
        private_retained,
        private_transient,
        source_finalization,
        wire_growth: encoded_growth,
        maximum_boot,
        launch,
    })
}

pub(super) const fn counter_scratch_data() -> usize {
    std::mem::size_of::<PacketNativeInvocationConstructionStorageData>()
        + 3 * std::mem::size_of::<OriginalSerializationStorageData>()
        + std::mem::size_of::<Projection>()
        + 2 * std::mem::size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>()
        + std::mem::size_of::<[usize; 10]>()
        + 2 * std::mem::size_of::<[&str; 3]>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
    use serde_json::json;

    #[test]
    fn actual_closed_purpose_tree_and_added_wrapper_fit_named_owner_phases() {
        let purpose = PacketNativeInvocationPurposeData {
            target: super::super::tests::target(),
            purpose: Purpose::Original,
        };
        let value = json!({"invocation":purpose});
        let mut observer = MetadataObserver::new();
        observer.observe(&value).unwrap();
        let actual = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
        let data = original_native_invocation_construction_storage_data(
            &purpose,
            b"{\"schema_version\":5}",
            4096,
            usize::MAX,
        )
        .unwrap();
        assert!(actual <= data.native_retained_requested_bytes());
        assert!(actual <= data.private_retained_requested_bytes());
        assert!(actual <= data.source_finalization_requested_bytes());
        assert!(data.maximum_private_boot_body_bytes() > 4096);
        assert!(data.launch_identity_data().encoded_bytes > b"{\"schema_version\":5}".len());
        assert!(
            original_native_invocation_construction_storage_data(
                &purpose,
                b"{}",
                512 * 1024,
                usize::MAX
            )
            .is_err()
        );
        assert!(
            original_native_invocation_construction_storage_data(&purpose, b"{}", 4096, 1).is_err()
        );
    }

    #[test]
    fn enlarged_allocation_rows_cover_full_decimal_widths_and_nullable_shape() {
        use crate::reference_packet::service::native_startup::{
            PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA, PacketNativeStartupAllocation,
            PacketNativeStartupAllocationRow,
        };
        use crucible_node_format::{U64, canonical};

        let quoted = allocation_rows(usize::MAX).unwrap();
        for number in [1, 9, 10, u64::MAX] {
            let row = PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(number),
                maximum_simultaneous_transient_bytes: U64::new(number),
                declared_counter_scratch_bytes: U64::new(number),
            };
            for restore_prepare in [None, Some(row)] {
                let value = json!({"native_startup_allocation": PacketNativeStartupAllocation {
                    schema: PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA.into(),
                    private_bootstrap: row,
                    native_birth: row,
                    restore_prepare,
                }});
                let encoded = canonical::canonical_json(&value).unwrap();
                let mut observer = MetadataObserver::new();
                observer.observe(&value).unwrap();
                let backing = requested_metadata_backing_storage_data(&observer.finish()).unwrap();
                assert!(encoded.len() <= quoted.maximum_encoded_bytes);
                assert!(backing <= quoted.requested_total().unwrap());
            }
        }
        assert!(allocation_rows(1).is_err());
    }
}
