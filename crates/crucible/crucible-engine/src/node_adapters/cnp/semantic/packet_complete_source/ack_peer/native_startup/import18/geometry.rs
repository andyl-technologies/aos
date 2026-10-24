//! Quotes the actual host import18 renderer independently of native funding.
//!
//! The opaque initial producer supplies derived body bounds, never a memory
//! grant. This module applies the defining JSON constructor layouts to those
//! same bodies. Every retained wire capacity and partial Source tree is a
//! separate R term. Disposable formatter/parser/writer work is T; literal
//! borrowed views and counter outputs are S. The original native escrow is
//! counted by Core once and is never used to pay these host constructors.

use super::*;
use crate::node_admission::OriginalNativeImport18StartupQuote;
use crucible_node_format::Bytes;
use crucible_node_transport::protocol_snapshot::raw_value_reparse::{
    JsonValueReparseConstructionData, quote_raw_json_data, raw_scanner_counter_scratch_data,
};
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18InitialFundingData, PacketNativeImport18PrebirthRecipeData,
    native_import18_initial_funding_counter_scratch_data,
    native_import18_launch_identity_counter_scratch_data,
    native_import18_launch_identity_projection_data,
};
use crucible_node_transport::retained_metadata::serialization_storage::{
    OriginalJsonValueStorageExtentData, original_json_value_storage_extent_counter_scratch_data,
    original_json_value_storage_extent_data,
};
use std::mem::size_of;

struct HostGeometry {
    recipe: PacketNativeImport18PrebirthRecipeData,
    initial: PacketNativeImport18InitialFundingData,
    host: [usize; 3],
    bodies: [usize; 3],
}

impl PacketCompleteSemanticSource {
    /// Names fixed metadata/scanner controls before any quote traversal.
    ///
    /// This contains no native funding or renderer allowance. Core separately
    /// admits the returned formatter prewalk before the full source quote.
    ///
    /// # Errors
    /// Refuses checked counter overflow.
    pub fn original_native_import18_startup_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms = [
            Self::original_native_startup_counter_scratch_data()?,
            Self::native_import18_declaration_counter_scratch_data(),
            Self::native_import18_recipe_metadata_counter_scratch_data(),
            native_import18_initial_funding_counter_scratch_data(),
            native_import18_launch_identity_counter_scratch_data(),
            raw_scanner_counter_scratch_data(),
            original_json_value_storage_extent_counter_scratch_data(),
            super::super::super::native_wire::PacketCompleteNativeImport18StartupWire::counter_scratch_data(),
            size_of::<HostGeometry>(),
            size_of::<Result<HostGeometry, RuntimeError>>(),
            size_of::<OriginalNativeImport18StartupQuote>(),
            size_of::<Result<OriginalNativeImport18StartupQuote, RuntimeError>>(),
            // Source and registration parser projections coexist with all
            // three independent future wire-body layout projections.
            size_of::<OriginalJsonValueStorageExtentData>(),
            size_of::<OriginalJsonValueStorageExtentData>(),
            size_of::<OriginalJsonValueStorageExtentData>(),
            size_of::<OriginalJsonValueStorageExtentData>(),
            size_of::<OriginalJsonValueStorageExtentData>(),
            size_of::<Result<OriginalJsonValueStorageExtentData, crucible_node_transport::ProviderError>>(),
            size_of::<JsonValueReparseConstructionData>(),
            size_of::<Result<JsonValueReparseConstructionData, crucible_node_transport::ProviderError>>(),
            size_of::<&Rc<Self>>(),
            size_of::<&PacketNative5SourceLaunch>(),
            size_of::<Ref<'static, Option<OriginalAckPeerBirth>>>(),
            size_of::<Result<Ref<'static, Option<OriginalAckPeerBirth>>, std::cell::BorrowError>>(),
            size_of::<&OriginalAckPeerBirth>(),
            size_of::<Result<&OriginalAckPeerBirth, RuntimeError>>(),
            size_of::<[usize; 3]>(),
            size_of::<[U64; 3]>(),
            size_of::<[Result<usize, std::num::TryFromIntError>; 3]>(),
            size_of::<std::array::IntoIter<usize, 3>>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<(usize, usize), crucible_node_transport::ProviderError>>(),
            size_of::<Result<(usize, usize), RuntimeError>>(),
            size_of::<(usize, usize, usize)>(),
            size_of::<(usize, usize, usize)>(),
            // Defining retained, transient and scratch sum arguments and
            // their consumed iterators are distinct fixed arithmetic controls.
            size_of::<[usize; 9]>(),
            size_of::<std::array::IntoIter<usize, 9>>(),
            size_of::<[usize; 20]>(),
            size_of::<std::array::IntoIter<usize, 20>>(),
            size_of::<[usize; 4]>(),
            size_of::<std::array::IntoIter<usize, 4>>(),
            size_of::<[usize; 5]>(),
            size_of::<std::array::IntoIter<usize, 5>>(),
            size_of::<Result<usize, std::num::TryFromIntError>>(),
            size_of::<blake3::Hash>(),
            size_of::<[u8; 32]>(),
        ];
        let controls = sum_argument_counter(&terms)?;
        sum(terms, usize::MAX).and_then(|bytes| add(bytes, controls, usize::MAX))
    }

    /// Quotes the disposable formatter window before the owning startup quote.
    ///
    /// Only bounded borrowed scans and existing immutable typed metadata are
    /// visited. No DOM, body bank, assigned phase or native owner is created.
    pub(crate) fn original_native_import18_startup_quote_prewalk_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<(usize, usize), RuntimeError> {
        let geometry = host_geometry(self, launch, maximum)?;
        Ok((geometry.host[1], geometry.host[2]))
    }

    pub(crate) fn original_native_import18_startup_quote_data(
        self: &Rc<Self>,
        launch: &PacketNative5SourceLaunch,
        encoded_launch: &[u8],
        maximum: usize,
    ) -> Result<OriginalNativeImport18StartupQuote, RuntimeError> {
        // The same actual renderer window was admitted by Core before this
        // baseline serializer can format a launch Bytes leaf.
        let geometry = host_geometry(self, launch, maximum)?;
        let baseline = self.original_native_startup_quote_data(launch, encoded_launch, maximum)?;
        Ok(OriginalNativeImport18StartupQuote {
            recipe: geometry.recipe,
            initial: geometry.initial,
            baseline,
            host: geometry.host,
            wire_body_maximum: geometry.bodies,
            launch_digest: *blake3::hash(encoded_launch).as_bytes(),
        })
    }
}

fn host_geometry(
    source: &Rc<PacketCompleteSemanticSource>,
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<HostGeometry, RuntimeError> {
    source.storage_origin_with_error::<RuntimeError>()?;
    if !source.is_original_native_import18_declaration_data()? {
        return Err(RuntimeError::UnsupportedFacet);
    }
    let recipe = source.original_native_import18_recipe_data()?;
    let initial = source.original_native_import18_initial_funding_data()?;
    if initial.recipe_identity_data() != recipe.identity_data() {
        return Err(RuntimeError::ForeignAuthority);
    }
    let bodies = initial
        .body_maximums_data()
        .map(|n| usize::try_from(n.get()));
    let [recipe_bytes, launch_bytes, boot_bytes] = bodies;
    let bodies = [
        recipe_bytes.map_err(|_| RuntimeError::ResourceLimit)?,
        launch_bytes.map_err(|_| RuntimeError::ResourceLimit)?,
        boot_bytes.map_err(|_| RuntimeError::ResourceLimit)?,
    ];
    if bodies.contains(&0) {
        return Err(RuntimeError::InvalidReceipt);
    }
    let slot = source
        .ack_peer_birth
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    birth.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
    if birth.native_startup.is_some() || birth.native_import18.is_some() {
        return Err(RuntimeError::DuplicateOperation);
    }

    let source_parse = extent(birth.source_birth.len())?;
    let host_parse = extent(birth.expected_host_registration.len())?;
    let source_extra = quote_raw_json_data(&birth.source_birth, maximum)
        .map_err(|_| RuntimeError::ResourceLimit)?
        .requested_storage_data();
    let host_extra = quote_raw_json_data(&birth.expected_host_registration, maximum)
        .map_err(|_| RuntimeError::ResourceLimit)?
        .requested_storage_data();
    let recipe_tree = extent(bodies[0])?;
    let launch_tree = extent(bodies[1])?;
    let boot_tree = extent(bodies[2])?;
    let (launch_formatter, launch_scratch) =
        native_import18_launch_identity_projection_data(launch)
            .map_err(|_| RuntimeError::ResourceLimit)?;

    // These exact three Source slots retain baseline, additions and wrapper
    // partials. Each is a subtree of the producer-bounded Boot18 output; before
    // merging, both independent root maps are charged in full. Replacement is
    // separately reserved to the same Boot bound by the actual finalizer.
    let retained = sum([
        sum(bodies, maximum)?,
        bodies[2],
        boot_tree.value_dom_requested_bytes,
        boot_tree.value_dom_requested_bytes,
        boot_tree.value_dom_requested_bytes,
        source_extra.0,
        NodeRuntime::capture_shared_allocation_storage::<PacketCompleteSemanticSource>(),
        crate::node_admission::InstalledConformancePlan::original_report_startup_plan_header_storage_data(),
        OriginalNativeImport18StartupMember::host_finalization_allocation_requested_data(),
    ], maximum)?;

    // Host registration is an ephemeral serializer input, not a modeled owner.
    // Its parser output and raw-reparse output live only in prepare_wire. The
    // Source parser result above instead stays in the real retained Birth slot.
    let transient = sum([
        recipe_tree.canonical_pass_requested_bytes().map_err(|_| RuntimeError::ResourceLimit)?,
        launch_tree.canonical_pass_requested_bytes().map_err(|_| RuntimeError::ResourceLimit)?,
        boot_tree.canonical_pass_requested_bytes().map_err(|_| RuntimeError::ResourceLimit)?,
        source_parse.value_dom_requested_bytes,
        source_extra.1,
        host_parse.value_dom_requested_bytes,
        host_extra.0,
        host_extra.1,
        launch_formatter,
        20, // The defining U64 decimal formatter, independent of its owned DOM string.
        44, // Padded-size upper bound for the actual unpadded key formatter.
        44, // Independent upper bound for the actual birth formatter.
        32, // Temporary key Bytes backing.
        32, // Temporary birth Bytes backing.
        size_of::<Bytes>(),
        size_of::<Bytes>(),
        OriginalNativeImport18Finalization::construction_transient_data(),
        super::super::super::native_wire::PacketCompleteNativeImport18StartupWire::construction_transient_data(),
        size_of::<OriginalNativeImport18StartupMember>(),
        size_of::<Option<OriginalNativeImport18StartupMember>>(),
    ], maximum)?;
    let scratch = sum(
        [
            PacketCompleteSemanticSource::original_native_import18_startup_counter_scratch_data()?,
            source_extra.2,
            host_extra.2,
            launch_scratch,
        ],
        maximum,
    )?;
    sum([retained, transient, scratch], maximum)?;
    birth.authenticate_unstarted_storage_phase_with_error::<RuntimeError>()?;
    Ok(HostGeometry {
        recipe,
        initial,
        host: [retained, transient, scratch],
        bodies,
    })
}

fn extent(bytes: usize) -> Result<OriginalJsonValueStorageExtentData, RuntimeError> {
    original_json_value_storage_extent_data(bytes).map_err(|_| RuntimeError::ResourceLimit)
}

fn add(left: usize, right: usize, maximum: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)
}

fn sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    terms
        .into_iter()
        .try_fold(0, |total, bytes| add(total, bytes, maximum))
}

// This is the actual local array plus the by-value sum argument/iterator. It
// describes explicit counter DATA only, never a recursive compiler stack frame.
fn sum_argument_counter<const N: usize>(terms: &[usize; N]) -> Result<usize, RuntimeError> {
    sum(
        [
            std::mem::size_of_val(terms),
            size_of::<[usize; N]>(),
            size_of::<std::array::IntoIter<usize, N>>(),
            size_of::<&[usize; N]>(),
            size_of::<Result<usize, RuntimeError>>(),
        ],
        usize::MAX,
    )
}
