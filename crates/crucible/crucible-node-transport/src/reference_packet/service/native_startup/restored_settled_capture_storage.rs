//! Binds the separate prepaid Capture17 carrier to its defining whole quote.
//!
//! Only the opaque defining producer can create StorageData. The portable
//! carrier is DATA: bootstrap must authenticate the actual Source MAC/current
//! member and later reconcile these exact fields with actual imported inputs.
//! Old startup16 reservation and its action credit are unchanged.

use super::{PacketNativeStartupAllocationRow, PacketRestoredSuffixReservationData};
use crate::ProviderError;
use crate::protocol_snapshot::restored_settled17::RestoredSettledNativeImportGeometryData;
use crate::reference_packet::service::{
    PacketNative5SourceLaunch,
    complete_restore::settled_recapture::PacketRestoredSettledCaptureOutputLimits,
};
use crucible_node_format::U64;
use serde::{Deserialize, Serialize};

/// Describes the exact fixed Capture17 advertisement in wrapper8/prefix17.
///
/// This is not a Rust-native layout on wire. Wire writes each field with its
/// explicit checked version/order/endian rules and authenticates the complete
/// new prefix. Matching numbers cannot mint a private reserve or Capture permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledNativeCarrierData {
    /// Selects exact native carrier edition17, encoded as one checked u64.
    pub version: U64,
    /// Commits to the actual complete canonical nested launch5 bytes.
    pub launch_identity: [u8; 32],
    /// Commits to all five imported fullrefs/byte extents and import class.
    pub import_identity: [u8; 32],
    /// Bounds the separately quoted future normalization bank, not a sixth input.
    pub normalization_maximum: U64,
    /// Bounds the actual nonrenewing native originals for this separate reserve.
    pub maximum_originals: U64,
    /// Independently funds the complete closed raw/typed native receive family.
    pub ingress: PacketNativeStartupAllocationRow,
    /// Funds only new action/output phases, excluding fixed imported custody.
    pub actions: PacketNativeStartupAllocationRow,
    /// Retains the exact five distinct output bank ceilings from the same launch.
    pub output_limits: PacketRestoredSettledCaptureOutputLimits,
}

impl PacketRestoredSettledNativeCarrierData {
    /// Checks the closed finite advertisement without creating any native grant.
    ///
    /// # Errors
    /// Refuses another edition, count outside the unchanged native256 ceiling,
    /// unsupported normalization bounds, invalid axes/output limits or overflow.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.version.get() != 17
            || self.maximum_originals.get() == 0
            || self.maximum_originals.get() > 256
            || self.normalization_maximum.get() == 0
            || self.normalization_maximum.get() > 65_536
            || self.ingress.requested_peak_data()? == 0
            || self.actions.requested_peak_data()? == 0
        {
            return Err(invalid());
        }
        self.output_limits.validate_data()
    }
}

/// Borrows exact already-funded rows without renewing their lifetime credits.
///
/// The genuine holder snapshots these before adding new17 construction. The
/// native-birth row already contains the old suffix reservation: that suffix is
/// a correspondence/subcomponent bound and is never summed a second time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRestoredSettledNativeExistingRowsData {
    /// Retains the actual complete baseline native-birth row, including old16.
    pub native_birth: PacketNativeStartupAllocationRow,
    /// Retains the actual independently funded Prepare phase, if selected.
    pub restore_prepare: Option<PacketNativeStartupAllocationRow>,
    /// Retains the exact nonrenewing old suffix count/ingress/action axes.
    pub suffix: PacketRestoredSuffixReservationData,
}

impl PacketRestoredSettledNativeExistingRowsData {
    /// Checks finite component geometry and genuine suffix coverage as DATA.
    ///
    /// # Errors
    /// Refuses malformed/overflowing rows or suffix axes outside native birth.
    /// This does not authenticate the holder, prefix or any remaining credit.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.native_birth.requested_peak_data()?;
        self.suffix.requested_bytes_data()?;
        let suffix = PacketNativeStartupAllocationRow {
            retained_requested_bytes: quantity(sum(&[
                extent(self.suffix.ingress.retained_requested_bytes)?,
                extent(self.suffix.actions.retained_requested_bytes)?,
            ])?)?,
            maximum_simultaneous_transient_bytes: quantity(sum(&[
                extent(self.suffix.ingress.maximum_simultaneous_transient_bytes)?,
                extent(self.suffix.actions.maximum_simultaneous_transient_bytes)?,
            ])?)?,
            declared_counter_scratch_bytes: quantity(sum(&[
                extent(self.suffix.ingress.declared_counter_scratch_bytes)?,
                extent(self.suffix.actions.declared_counter_scratch_bytes)?,
            ])?)?,
        };
        self.native_birth.authenticate_actual_data(&suffix)?;
        if let Some(prepare) = self.restore_prepare {
            prepare.requested_peak_data()?;
        }
        Ok(())
    }

    fn bind_identity_data(&self, hash: &mut blake3::Hasher) {
        for row in [
            Some(self.native_birth),
            self.restore_prepare,
            Some(self.suffix.ingress),
            Some(self.suffix.actions),
        ] {
            hash.update(&[u8::from(row.is_some())]);
            if let Some(row) = row {
                hash.update(&row.retained_requested_bytes.get().to_be_bytes());
                hash.update(&row.maximum_simultaneous_transient_bytes.get().to_be_bytes());
                hash.update(&row.declared_counter_scratch_bytes.get().to_be_bytes());
            }
        }
        hash.update(&self.suffix.maximum_originals.get().to_be_bytes());
    }
}

/// Bounds a separate Source-process decoder of the same native outputs.
///
/// This fixed DATA result is independently added to the host/Source census; the
/// native reserve cannot pay for a second process. It grants no allocation or
/// permits accepting a graph whose preflight exceeds these same typed bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRestoredSettledNativeOutputValidationStorageData {
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum_typed_graph: usize,
    output_limits: PacketRestoredSettledCaptureOutputLimits,
}

impl PacketRestoredSettledNativeOutputValidationStorageData {
    /// Returns independent host retained backing, excluding the inline root.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }
    /// Returns separately admitted host parser/canonical/typed-build peak.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }
    /// Returns actual defining strict reader/current-model fixed views.
    pub const fn declared_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
    /// Borrows the same five independent output limits that define this row.
    pub const fn output_limits_data(&self) -> &PacketRestoredSettledCaptureOutputLimits {
        &self.output_limits
    }
    /// Returns the independent per-cut typed-graph bound checked before reconstruction.
    pub const fn maximum_typed_graph_requested_bytes_data(&self) -> usize {
        self.maximum_typed_graph
    }
}

/// Borrows real defining inputs before any new private/native child is launched.
pub struct PacketRestoredSettledNativeConstructionInputs<'a> {
    /// Borrows the actual selected complete launch, not a reconstructed DTO.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows its same retained canonical launch5 bank.
    pub canonical_launch5: &'a [u8],
    /// Borrows defining validated import geometry and its exact five-role cut.
    pub import: &'a RestoredSettledNativeImportGeometryData,
    /// Borrows exact genuine prior native rows, with no suffix double-count.
    pub existing_rows: &'a PacketRestoredSettledNativeExistingRowsData,
    /// Bounds all actual auxiliary upload/Capture/confirmation originals.
    pub maximum_originals: usize,
    /// Borrows the unchanged independently installed requested-storage ceiling.
    pub maximum_requested_bytes: usize,
}

/// Retains the defining whole quote and exact portable carrier as DATA.
///
/// No public constructor or deserializer can substitute arbitrary numeric rows.
/// Actual private bootstrap/current native admission is a separate capability.
#[derive(Serialize)]
pub struct PacketRestoredSettledNativeStorageData {
    pub(super) carrier: PacketRestoredSettledNativeCarrierData,
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
    pub(super) frame_bytes: usize,
    pub(super) metadata_rows: [usize; 2],
    pub(super) requested: usize,
    pub(super) existing_rows: PacketRestoredSettledNativeExistingRowsData,
}

impl PacketRestoredSettledNativeStorageData {
    /// Reports the fixed inline quote without reconstructing a native owner.
    ///
    /// The enclosing holder already owns this header. Its defining field roster
    /// contains Copy DATA only, so it contributes no dynamic capacity rows. A
    /// new owning field must replace this contract with an explicit bank walk.
    /// Admit [`Self::retained_metadata_counter_scratch_data`] before observing.
    pub fn retained_metadata_data(
        &self,
    ) -> crate::retained_metadata::RetainedProtocolMetadataFacts {
        let Self {
            carrier,
            retained,
            transient,
            scratch,
            frame_bytes,
            metadata_rows,
            requested,
            existing_rows,
        } = self;

        fn inline<T: Copy>(_: &T) {}

        inline(carrier);
        inline(retained);
        inline(transient);
        inline(scratch);
        inline(frame_bytes);
        inline(metadata_rows);
        inline(requested);
        inline(existing_rows);
        crate::retained_metadata::RetainedProtocolMetadataFacts::default()
    }

    /// Names the actual inline-field loans, helper argument and returned facts.
    pub fn retained_metadata_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&PacketRestoredSettledNativeCarrierData>()
            + 5 * size_of::<&usize>()
            + size_of::<&[usize; 2]>()
            + size_of::<&PacketRestoredSettledNativeExistingRowsData>()
            + size_of::<&usize>()
            + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
    }

    /// Borrows all exact advertised fields for the new writer and MAC boundary.
    pub const fn carrier_data(&self) -> &PacketRestoredSettledNativeCarrierData {
        &self.carrier
    }

    /// Checks known initial owners against the genuine complete native birth.
    ///
    /// The imported decoder/raw/normalization demand is not known at this cut.
    /// This lower bound proves only the compiled reserve owner and quote header,
    /// beside the complete ingress/action and wrapper construction reservations.
    /// The private bootstrap caller authenticates the Source MAC and same raw
    /// wrapper before this check; exact import replay remains mandatory later.
    ///
    /// # Errors
    /// Refuses invalid rows, overflow, or a short native-birth component. No
    /// numeric match creates a private reserve or an action spend.
    pub(crate) fn authenticate_initial_owner_admission_data(
        existing: &PacketRestoredSettledNativeExistingRowsData,
        carrier: &PacketRestoredSettledNativeCarrierData,
        construction: &super::PacketNativeSettledConstructionStorageData,
        final_native_birth: &PacketNativeStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        existing.validate_data()?;
        carrier.validate_data()?;
        let minimum = PacketNativeStartupAllocationRow {
            retained_requested_bytes: quantity(sum(&[
                extent(existing.native_birth.retained_requested_bytes)?,
                extent(carrier.ingress.retained_requested_bytes)?,
                extent(carrier.actions.retained_requested_bytes)?,
                construction.native_retained_requested_bytes(),
                std::mem::size_of::<Self>(),
                crate::reference_packet::service::ack_emitter::original_restored_settled_native_owner_header_data(),
            ])?)?,
            maximum_simultaneous_transient_bytes: quantity(sum(&[
                extent(existing.native_birth.maximum_simultaneous_transient_bytes)?,
                extent(carrier.ingress.maximum_simultaneous_transient_bytes)?,
                extent(carrier.actions.maximum_simultaneous_transient_bytes)?,
                construction.native_transient_requested_bytes(),
            ])?)?,
            declared_counter_scratch_bytes: quantity(sum(&[
                extent(existing.native_birth.declared_counter_scratch_bytes)?,
                extent(carrier.ingress.declared_counter_scratch_bytes)?,
                extent(carrier.actions.declared_counter_scratch_bytes)?,
                super::original_native_settled_carrier_counter_scratch_data(),
            ])?)?,
        };
        final_native_birth.authenticate_actual_data(&minimum)
    }

    /// Returns fixed construction axes excluded from spendable action credit.
    ///
    /// These are prospective imported decoder/raw/normalization bounds and the
    /// compiled reserve-owner header, not a claim that those owners are already
    /// initialized. This DATA view never seeds or renews the native action ledger.
    ///
    /// # Errors
    /// Refuses a malformed internal partition or checked arithmetic overflow.
    pub fn fixed_construction_requested_axes_data(&self) -> Result<[usize; 3], ProviderError> {
        let ingress = self.carrier.ingress;
        let actions = self.carrier.actions;
        let totals = [self.retained, self.transient, self.scratch];
        let variable = [
            sum(&[
                extent(ingress.retained_requested_bytes)?,
                extent(actions.retained_requested_bytes)?,
                std::mem::size_of::<Self>(),
            ])?,
            sum(&[
                extent(ingress.maximum_simultaneous_transient_bytes)?,
                extent(actions.maximum_simultaneous_transient_bytes)?,
            ])?,
            sum(&[
                extent(ingress.declared_counter_scratch_bytes)?,
                extent(actions.declared_counter_scratch_bytes)?,
            ])?,
        ];
        Ok([
            totals[0].checked_sub(variable[0]).ok_or_else(invalid)?,
            totals[1].checked_sub(variable[1]).ok_or_else(invalid)?,
            totals[2].checked_sub(variable[2]).ok_or_else(invalid)?,
        ])
    }

    /// Borrows the exact pre-new17 snapshot authenticated in wrapper8.
    pub const fn existing_rows_data(&self) -> &PacketRestoredSettledNativeExistingRowsData {
        &self.existing_rows
    }

    /// Returns independently requested complete persistent native construction.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independently requested peak temporary native construction.
    pub const fn transient_requested_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the defining native quote/parser/writer fixed-view obligation.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns all five exact independent new output ceilings.
    pub const fn output_limits_data(&self) -> &PacketRestoredSettledCaptureOutputLimits {
        &self.carrier.output_limits
    }

    /// Returns the same negotiated original frame ceiling.
    pub const fn maximum_frame_bytes_data(&self) -> usize {
        self.frame_bytes
    }

    /// Returns the separately funded before/after capacity and alias row limits.
    pub const fn metadata_row_limits_data(&self) -> [usize; 2] {
        self.metadata_rows
    }

    /// Returns the checked complete requested sum, independent of native authority.
    pub const fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Quotes a second, independently funded Source decoder of current output.
    ///
    /// The old native-birth row already contains old16; its scalar axes bound
    /// existing owned graph backing without renewing that reservation. Native
    /// must first walk/count the actual current graph within those genuine
    /// lifetime rows. The strict host preflight independently rejects excessive
    /// capacity/alias/model demand before constructing any typed owner.
    ///
    /// # Errors
    /// Refuses invalid prior rows, checked overflow or unrepresentable output
    /// syntax. The Source must add this whole result to its own current census.
    pub fn source_output_validation_data(
        &self,
    ) -> Result<PacketRestoredSettledNativeOutputValidationStorageData, ProviderError> {
        use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
        self.existing_rows.validate_data()?;
        let prior = extent(self.existing_rows.native_birth.retained_requested_bytes)?;
        let prepare = self
            .existing_rows
            .restore_prepare
            .map(|row| extent(row.retained_requested_bytes))
            .transpose()?
            .unwrap_or(0);
        let maximum_typed_graph = sum(&[prior, prepare, self.retained])?;
        // Each cut independently retains source alias summaries and a concrete
        // target-construction bitmap and selected Arc cache slots. Payloads and
        // partially filled selected slices have separate recursive bounds.
        // The bitmap prevents alias-equal Arc owners
        // from being charged repeatedly, without confusing source group DATA
        // with permission to reconstruct an already-retained target allocation.
        let summary_and_target = sum(&[
            std::mem::size_of::<crate::protocol_snapshot::restored_settled17::aliases::RestoredSettledNative17AliasSummary>(),
            std::mem::size_of::<bool>(),
            std::mem::size_of::<Option<std::sync::Arc<[crucible_node_format::ExtensionSelection]>>>(),
        ])?;
        let alias_summaries = mul(sum(&self.metadata_rows)?, summary_and_target)?;
        let limits = &self.carrier.output_limits;
        let mut raw = 0usize;
        let mut transient = 0usize;
        let mut syntax_scratch = 0usize;
        for bytes in [
            limits.native_snapshot_bytes,
            limits.current_control_bytes,
            limits.native_before_bytes,
            limits.anchor_bytes,
            limits.native_after_bytes,
        ] {
            let bytes = extent(bytes)?;
            let syntax = original_json_value_storage_extent_data(bytes)?;
            raw = add(raw, bytes)?;
            transient = add(transient, syntax.canonical_pass_requested_bytes()?)?;
            syntax_scratch = add(syntax_scratch, syntax.declared_counter_scratch_bytes)?;
        }
        // Each independently admitted reader owns a raw evidence copy and its
        // concrete Control/lineage target in addition to the outer five banks.
        // Unused DOM capacity does not pay for either actual target or raw bank.
        let graph_raw = sum(&[
            extent(limits.native_before_bytes)?,
            extent(limits.native_after_bytes)?,
        ])?;
        let graph_targets = mul(2, maximum_typed_graph)?;
        // Both lazily retained decoder headers are actual heap slots, separate
        // from selected model backing and the enclosing inline Source owner.
        let graph_headers = mul(
            2,
            std::mem::size_of::<Option<crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17DecodeAttempt>>(),
        )?;
        let role_references = mul(
            5,
            sum(&[
                "blake3-256".len(),
                "cnp.blob.v1".len(),
                64,
                "application/json".len(),
            ])?,
        )?;
        Ok(PacketRestoredSettledNativeOutputValidationStorageData {
            retained:sum(&[raw,graph_raw,graph_targets,graph_headers,alias_summaries,role_references])?,
            // Native decoder roots are independent pure constructor outputs;
            // neither retained model backing nor heap-slot R pays this T window.
            transient: sum(&[
                transient,
                maximum_typed_graph,
                crate::protocol_snapshot::restored_settled17::restored_settled_native17_decode_construction_transient_bytes_data(),
            ])?,
            scratch:sum(&[syntax_scratch,crate::protocol_snapshot::restored_settled17::restored_settled_native17_counter_scratch_data()])?,
            maximum_typed_graph,
            output_limits:self.carrier.output_limits,
        })
    }

    /// Repeats the defining projection over the same actual retained inputs.
    ///
    /// # Errors
    /// Refuses changed identities, input geometry, phase rows, policy or limits.
    /// The enclosing issuer still checks actual Source/member ownership.
    pub fn authenticate_same_inputs_data(
        &self,
        inputs: &PacketRestoredSettledNativeConstructionInputs<'_>,
    ) -> Result<(), ProviderError> {
        let actual = original_restored_settled_native_storage_data(inputs)?;
        if self.carrier != actual.carrier
            || self.retained != actual.retained
            || self.transient != actual.transient
            || self.scratch != actual.scratch
            || self.frame_bytes != actual.frame_bytes
            || self.metadata_rows != actual.metadata_rows
            || self.requested != actual.requested
            || self.existing_rows != actual.existing_rows
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Compares the complete received carrier with the genuine defining quote.
    ///
    /// # Errors
    /// Refuses any changed identity, row axis, original count or output limit.
    /// This comparison neither verifies a Source MAC nor creates native credit.
    pub fn authenticate_received_carrier_data(
        &self,
        received: &PacketRestoredSettledNativeCarrierData,
    ) -> Result<(), ProviderError> {
        received.validate_data()?;
        if received != &self.carrier {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored settled native17 carrier or defining row differs")
}

/// Quotes the distinct preChild Capture17 receive and graph/output construction.
///
/// All new owners are added independently. Imported decoder/raw/normalization
/// demand and the reserve header remain in full native construction, outside
/// the spendable action row. Repeated metadata banks and the five outputs receive
/// no alias discount. The actual current graph must still be walked and counted under
/// these admitted axes before its serializer runs. A graph that cannot fit is
/// refused without raising these ceilings or borrowing old16 action credit.
///
/// The same actual registered holder authenticates typed/raw launch identity
/// around this pure call. Private prefix/wrapper construction is a separately
/// defining Core/Wire phase, not hidden in this native Capture row.
///
/// # Errors
/// Refuses missing full17 declaration, invalid launch/storage/import geometry,
/// empty or excessive originals/raw launch, checked overflow or policy excess.
pub fn original_restored_settled_native_storage_data(
    input: &PacketRestoredSettledNativeConstructionInputs<'_>,
) -> Result<PacketRestoredSettledNativeStorageData, ProviderError> {
    use crate::retained_metadata::{
        aliases::MetadataAliasBank,
        records::{MetadataCapacityRecord, MetadataRecordBank},
        serialization_storage::original_json_value_storage_extent_data,
    };
    use std::mem::size_of;
    input.launch.storage.validate(&input.launch.limits)?;
    input.existing_rows.validate_data()?;
    let output_limits = PacketRestoredSettledCaptureOutputLimits::from_launch_data(input.launch)?;
    if input.canonical_launch5.is_empty()
        || input.canonical_launch5.len() > 1024 * 1024
        || input.maximum_originals == 0
        || input.maximum_originals > 256
        || quantity(input.maximum_originals)? > input.launch.limits.requests
    {
        return Err(invalid());
    }
    let frame_bytes =
        usize::try_from(input.launch.limits.frame_bytes.get()).map_err(|_| invalid())?;
    let metadata = input
        .launch
        .protocol_metadata_limits
        .as_ref()
        .ok_or_else(invalid)?;
    metadata.validate_data()?;
    let metadata_rows = [
        extent(metadata.native_before_rows)?,
        extent(metadata.native_after_rows)?,
    ];
    let one_ingress = super::original_restored_settled_action_ingress_row_data(frame_bytes)?;
    let ingress = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(mul(
            input.maximum_originals,
            extent(one_ingress.retained_requested_bytes)?,
        )?)?,
        maximum_simultaneous_transient_bytes: one_ingress.maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes: one_ingress.declared_counter_scratch_bytes,
    };

    let outputs = [
        extent(output_limits.native_snapshot_bytes)?,
        extent(output_limits.current_control_bytes)?,
        extent(output_limits.native_before_bytes)?,
        extent(output_limits.anchor_bytes)?,
        extent(output_limits.native_after_bytes)?,
    ];
    let mut output_bytes = 0usize;
    let mut encoding_transient = 0usize;
    let mut encoding_scratch = 0usize;
    for output in outputs {
        output_bytes = add(output_bytes, output)?;
        let syntax = original_json_value_storage_extent_data(output)?;
        encoding_transient = add(encoding_transient, syntax.canonical_pass_requested_bytes()?)?;
        encoding_scratch = add(encoding_scratch, syntax.declared_counter_scratch_bytes)?;
    }
    let mut metadata_bytes = 0usize;
    for rows in metadata_rows {
        metadata_bytes = sum(&[
            metadata_bytes,
            mul(rows, size_of::<MetadataCapacityRecord>())?,
            MetadataAliasBank::reservation_requested_bytes(rows)?,
            size_of::<MetadataRecordBank>(),
            size_of::<MetadataAliasBank>(),
        ])?;
    }
    let decoder = input.import.decoder_requested_axes_data()?;
    // Raw immutable input copies and future mapping normalization remain
    // independent from the historical decoder's typed backing demand.
    let import_raw = sum(&input.import.archived_input_byte_extents_data())?;
    // Fixed construction stays in the complete native birth, but never enters
    // the once-action ledger. Import/normalization capacity cannot pay again for
    // later Control, Blob, checkpoint, prefix or output allocations.
    let fixed_construction = [
        sum(&[
            decoder[0], import_raw, input.import.normalization_maximum_data(),
            crate::reference_packet::service::ack_emitter::original_restored_settled_native_owner_header_data(),
        ])?,
        decoder[1],
        decoder[2],
    ];
    // Upload primitives and ordinary transport have different owners from
    // ingress and the five output banks. Reserve their complete finite future
    // demand independently before native birth; no later request can convert an
    // output ceiling or imported backing into receiver allocation credit.
    let uploads = super::capture_upload17_future::future_storage_data(
        input.launch,
        input.maximum_originals,
        *blake3::hash(input.canonical_launch5).as_bytes(),
        input.maximum_requested_bytes,
    )?;
    let upload_axes = uploads.lifetime_axes_data();
    let actions = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(sum(&[
            extent(upload_axes.retained_requested_bytes)?,
            output_bytes,
            metadata_bytes,
            mul(
                5,
                size_of::<crucible_node_format::ContentRef>() + 10 + 11 + 64 + 16,
            )?,
            size_of::<super::restored_settled_capture_output::NativeRestoredSettledCaptureOutputs>(
            ),
        ])?)?,
        maximum_simultaneous_transient_bytes: quantity(sum(&[
            encoding_transient,
            extent(upload_axes.maximum_simultaneous_transient_bytes)?,
        ])?)?,
        declared_counter_scratch_bytes: quantity(sum(&[
            encoding_scratch,
            extent(upload_axes.declared_counter_scratch_bytes)?,
            original_restored_settled_native_storage_counter_scratch_data(),
        ])?)?,
    };
    let mut identity =
        blake3::Hasher::new_derive_key("source-private.native17-import-and-existing-rows/17");
    identity.update(&input.import.identity_data());
    input.existing_rows.bind_identity_data(&mut identity);
    let carrier = PacketRestoredSettledNativeCarrierData {
        version: U64::new(17),
        launch_identity: *blake3::hash(input.canonical_launch5).as_bytes(),
        import_identity: *identity.finalize().as_bytes(),
        normalization_maximum: quantity(input.import.normalization_maximum_data())?,
        maximum_originals: quantity(input.maximum_originals)?,
        ingress,
        actions,
        output_limits,
    };
    carrier.validate_data()?;
    let [retained, transient, scratch] = native_storage_totals_data(
        ingress,
        fixed_construction,
        actions,
        size_of::<PacketRestoredSettledNativeStorageData>(),
    )?;
    let requested = sum(&[retained, transient, scratch])?;
    if requested > input.maximum_requested_bytes {
        return Err(invalid());
    }
    Ok(PacketRestoredSettledNativeStorageData {
        carrier,
        retained,
        transient,
        scratch,
        frame_bytes,
        metadata_rows,
        requested,
        existing_rows: *input.existing_rows,
    })
}

/// Names the defining fixed input, row, hash, iterator and output owner views.
pub fn original_restored_settled_native_storage_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<PacketRestoredSettledNativeConstructionInputs<'static>>()
        + size_of::<PacketRestoredSettledNativeStorageData>()
        + size_of::<PacketRestoredSettledNativeCarrierData>()
        + size_of::<PacketRestoredSettledNativeExistingRowsData>()
        + size_of::<PacketRestoredSettledNativeOutputValidationStorageData>()
        + size_of::<Option<PacketNativeStartupAllocationRow>>()
        + size_of::<[Option<PacketNativeStartupAllocationRow>; 4]>()
        + size_of::<std::array::IntoIter<Option<PacketNativeStartupAllocationRow>, 4>>()
        + size_of::<Result<PacketRestoredSettledNativeStorageData, ProviderError>>()
        + size_of::<PacketNativeStartupAllocationRow>() * 3
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<[usize; 2]>()
        + size_of::<std::array::IntoIter<usize, 2>>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Option<&usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + RestoredSettledNativeImportGeometryData::counter_scratch_data()
        + PacketRestoredSettledCaptureOutputLimits::counter_scratch_data()
        + size_of::<super::PacketNativeSettledConstructionStorageData>()
        + size_of::<&super::PacketNativeSettledConstructionStorageData>()
        + size_of::<crate::protocol_snapshot::owned11::typed::Fields<'static>>()
        + size_of::<[usize; 3]>() * 4
        + size_of::<[usize; 4]>() * 2
        + size_of::<[usize; 6]>()
        + size_of::<&PacketRestoredSettledNativeCarrierData>()
        + size_of::<&PacketRestoredSettledNativeExistingRowsData>()
        + size_of::<&PacketNativeStartupAllocationRow>()
        + super::original_restored_settled_action_counter_scratch_data()
        + super::restored_settled_capture_output::counter_scratch_data()
        + super::capture_upload17_future::counter_scratch_data()
}

// This partition changes no serialized field or StorageData layout. Both real
// Source prebirth quotation and native import replay call this same producer.
fn native_storage_totals_data(
    ingress: PacketNativeStartupAllocationRow,
    fixed: [usize; 3],
    actions: PacketNativeStartupAllocationRow,
    header: usize,
) -> Result<[usize; 3], ProviderError> {
    ingress.requested_peak_data()?;
    actions.requested_peak_data()?;
    Ok([
        sum(&[
            extent(ingress.retained_requested_bytes)?,
            fixed[0],
            extent(actions.retained_requested_bytes)?,
            header,
        ])?,
        sum(&[
            extent(ingress.maximum_simultaneous_transient_bytes)?,
            fixed[1],
            extent(actions.maximum_simultaneous_transient_bytes)?,
        ])?,
        sum(&[
            extent(ingress.declared_counter_scratch_bytes)?,
            fixed[2],
            extent(actions.declared_counter_scratch_bytes)?,
        ])?,
    ])
}

fn add(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_add(b).ok_or_else(invalid)
}

fn mul(a: usize, b: usize) -> Result<usize, ProviderError> {
    a.checked_mul(b).ok_or_else(invalid)
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0, |a, b| add(a, *b))
}

fn extent(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get()).map_err(|_| invalid())
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| invalid())?))
}

#[cfg(test)]
mod action_partition_tests {
    use super::*;

    fn row(retained: u64, transient: u64, scratch: u64) -> PacketNativeStartupAllocationRow {
        PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(retained),
            maximum_simultaneous_transient_bytes: U64::new(transient),
            declared_counter_scratch_bytes: U64::new(scratch),
        }
    }

    #[test]
    fn fixed_partition_preserves_full_construction_without_action_credit() {
        let ingress = row(11, 13, 17);
        let actions = row(19, 23, 29);
        let fixed = [31, 37, 41];
        let header = 43;

        let partitioned = native_storage_totals_data(ingress, fixed, actions, header).unwrap();
        let old_mixed_actions = row(19 + 31, 23 + 37, 29 + 41);
        let old_totals =
            native_storage_totals_data(ingress, [0; 3], old_mixed_actions, header).unwrap();

        assert_eq!(partitioned, old_totals);
        assert_eq!(partitioned, [104, 73, 87]);
        let larger_import =
            native_storage_totals_data(ingress, [131, 137, 141], actions, header).unwrap();
        assert_eq!(larger_import, [204, 173, 187]);
        assert_eq!(actions, row(19, 23, 29));
        assert!(native_storage_totals_data(ingress, [usize::MAX, 0, 0], actions, header).is_err());
    }

    #[test]
    fn unchanged_numeric_ledger_cannot_spend_excluded_import_or_renew_actions() {
        // This numeric ledger is DATA, not a live native/Source action scope.
        let ingress = row(11, 13, 17);
        let actions = row(19, 23, 29);
        let admitted = PacketRestoredSuffixReservationData {
            maximum_originals: U64::new(2),
            ingress: row(22, 13, 17),
            actions,
        };
        let mut attempted_import_spend =
            super::super::OriginalRestoredSuffixBudget::new_data(admitted).unwrap();
        attempted_import_spend.begin_ingress_data(ingress).unwrap();
        assert!(
            attempted_import_spend
                .begin_action_data(row(50, 23, 29))
                .is_err()
        );
        assert!(attempted_import_spend.begin_action_data(actions).is_err());

        let mut lifetime = super::super::OriginalRestoredSuffixBudget::new_data(admitted).unwrap();
        lifetime.begin_ingress_data(ingress).unwrap();
        lifetime.begin_action_data(actions).unwrap();
        lifetime.complete_publication_data().unwrap();
        lifetime.begin_ingress_data(ingress).unwrap();
        assert!(lifetime.begin_action_data(row(1, 23, 29)).is_err());
    }
}
