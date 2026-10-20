//! Private original Source own-floor measurement and actual Journal headroom DATA.
//!
//! Ledger owns branch eligibility. This adapter measures every derived branch
//! through the existing engine with the actual immutable Source5 value width.
//! The Source union adapter reuses this fold for complete ordinary association
//! and transaction DATA. Original admission membership, challenge debt, physical
//! funding and live custody remain independent unresolved obligations. There is
//! no conversion from these measurements to a writer, receipt or live owner.

use aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservations;
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRequestV3,
    ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5, OriginalSourceCapacityBudgetsV5,
    OriginalSourceCapacityRecordV5,
};

use std::collections::BTreeMap;

use aos_sandbox_source_provider_ledger::ledger::{
    native_completion::{
        OriginalSourceOwnerTransactionV5, SourcePreRequestedColdPhaseV1 as ColdPhase,
        propose_original_source_applying_v5,
    },
    native_held_completion::{
        OriginalSourceBeforeDependencyV5, OriginalSourceContinuationAlternativeV5,
        OriginalSourceContinuationDataV5, OriginalSourceContinuationKindV5,
        OriginalSourceContinuationPrefixV5, SourceNativeHeldStepV1 as SourceStep,
    },
};

#[cfg(test)]
use super::super::check_transfer;
use super::super::invalid;
use super::{
    ChangeShape, JournalError, JournalLimits, JournalRecord, JournalTransaction, MeasuredAppends,
    MeasurementValueAppend, NativeBeforeAfterValueRef, NativeHeldCapacityGeometryV3,
    NativeHeldCapacityStepV3, NativeHeldCapacityUsageV3, NativeSuffixValueRef, RecordNamespace,
    add, encoded_transaction_append_bytes, measure_value_appends_with_prefixes,
    require_change_images, validate_transaction,
};
#[cfg(test)]
use super::{
    MeasurementAppend, NativeHeldCapacityChangeV3,
    measure_appends_with_prefixes,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[doc(hidden)]
/// Carries bounded historical measurement DATA without reserving capacity.
pub struct CoupledPrefix {
    /// Retains this measured DATA field without a capacity grant.
    pub bytes: i128,
    /// Retains this measured DATA field without a capacity grant.
    pub records: i64,
}

/// Borrows the exact historical Source owner rows as comparison DATA.
#[doc(hidden)]
pub type OwnerView<'a> = BTreeMap<&'a [u8], &'a [u8]>;

/// Borrows one measured branch without providing a physical funding token.
pub struct OriginalSourceMeasuredAlternativeV5 {
    /// Retains this measured DATA field without a capacity grant.
    pub owner: NativeHeldCapacityGeometryV3,
    /// Retains this measured DATA field without a capacity grant.
    pub coupled: Vec<CoupledPrefix>,
    /// Retains this measured DATA field without a capacity grant.
    pub maximum_coupled_growth_bytes: u64,
    /// Retains this measured DATA field without a capacity grant.
    pub maximum_coupled_growth_records: u64,
    /// Retains this measured DATA field without a capacity grant.
    pub maximum_key_bytes: usize,
    /// Retains this measured DATA field without a capacity grant.
    pub maximum_record_payload_bytes: usize,
    /// Retains this measured DATA field without a capacity grant.
    pub frames: u64,
    /// Retains this measured DATA field without a capacity grant.
    pub poison: bool,
    /// Retains this measured DATA field without a capacity grant.
    pub independent_cut_required: bool,
    /// Retains this measured DATA field without a capacity grant.
    pub original_custody_required: bool,
}

/// Keeps bounded geometry and its incomplete physical-funding obligations private.
pub struct OriginalSourceGeometryDataV5 {
    /// Retains this measured DATA field without a capacity grant.
    pub alternatives: Vec<OriginalSourceMeasuredAlternativeV5>,
    /// Retains this measured DATA field without a capacity grant.
    pub normal: NativeHeldCapacityGeometryV3,
    /// Retains this measured DATA field without a capacity grant.
    pub poison: NativeHeldCapacityGeometryV3,
    /// Retains this measured DATA field without a capacity grant.
    pub remaining: Option<NativeHeldCapacityRequestV3>,
    /// Retains this measured DATA field without a capacity grant.
    pub staged_peak_bytes: u64,
    /// Retains this measured DATA field without a capacity grant.
    pub staged_peak_records: u64,
    /// Retains this measured DATA field without a capacity grant.
    pub other_frames: u64,
    /// Retains this measured DATA field without a capacity grant.
    pub ordinary_association_required: bool,
    /// Retains this measured DATA field without a capacity grant.
    pub original_membership_required: bool,
}

impl OriginalSourceGeometryDataV5 {
    /// Derives initial envelope DATA without inventing a provisionally funded floor.
    ///
    /// The canonical floor's fixed portion and reservation-key codec determine
    /// its width. The actual retained provenance supplies the variable portion.
    /// All physical admission and opened headroom checks remain with the writer.
    pub fn measure_initial_envelopes(
        continuation: &OriginalSourceContinuationDataV5,
        limits: JournalLimits,
    ) -> Result<OriginalSourceCapacityBudgetsV5, JournalError> {
        if continuation.prefix() != OriginalSourceContinuationPrefixV5::Applying
            || continuation.original().is_none()
        {
            return Err(invalid("original Source initial measurement requires Applying"));
        }
        let fixed_width = ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5
            - aos_sandbox_source_provider_ledger::ledger::native_completion::
                MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5;
        let floor_width = fixed_width
            .checked_add(continuation.provenance().to_canonical_bytes().len())
            .ok_or(JournalError::JournalTooLarge)?;
        let key_width = aos_sandbox_protocol::domain_ledger::capacity::reservation_key([0; 32]).len();
        let owners = continuation.current_records().collect::<OwnerView<'_>>();
        let measured = measure_envelopes(
            continuation, &owners, limits, key_width, floor_width, true,
        )?;
        if measured.normal.transactions.max(measured.poison.transactions) != 20 {
            return Err(invalid("original Source initial continuation count"));
        }

        Ok(OriginalSourceCapacityBudgetsV5 {
            terminal_records: measured.normal.records,
            terminal_bytes: measured.normal.append_bytes,
            poison_records: measured.poison.records,
            poison_bytes: measured.poison.append_bytes,
        })
    }

    /// Measures every reducer-derived branch without Journal usage or authority.
    ///
    /// # Errors
    ///
    /// Rejects changed origin/bindings/capsules, incomplete geometry, insufficient
    /// supplied debt, codec/measurement limits or bounded arithmetic exhaustion.
    pub fn measure_remaining(
        floor: &OriginalSourceCapacityRecordV5,
        continuation: &OriginalSourceContinuationDataV5,
        limits: JournalLimits,
    ) -> Result<Self, JournalError> {
        let owners = continuation.current_records().collect::<OwnerView<'_>>();
        let floor_present = !continuation
            .alternatives()
            .iter()
            .all(|alternative| alternative.edges().is_empty());
        measure_remaining(floor, continuation, &owners, limits, floor_present)
    }

    /// Checks immutable original/cold capsule DATA without measuring retired debt.
    ///
    /// # Errors
    ///
    /// Rejects changed provenance, immutable bindings or copied initial floor.
    pub fn validate_origin_data(
        floor: &OriginalSourceCapacityRecordV5,
        continuation: &OriginalSourceContinuationDataV5,
    ) -> Result<(), JournalError> {
        if floor.original_provenance() != continuation.provenance() {
            return Err(invalid("original Source geometry provenance changed"));
        }
        validate_original_bindings(floor, continuation)?;
        validate_cold_capsule(floor, continuation)
    }

    /// Checks measured complete branches against actual usage and sequence DATA.
    ///
    /// # Errors
    ///
    /// Rejects any opened ceiling, coupled retained peak or sequence exhaustion.
    pub fn require_usage_headroom(
        &self,
        limits: JournalLimits,
        usage: NativeHeldCapacityUsageV3,
        next_sequence: u64,
        other_frames: u64,
    ) -> Result<(), JournalError> {
        for alternative in &self.alternatives {
            alternative.owner.require_headroom(limits, usage)?;
            require_coupled_headroom(limits, usage, alternative)?;
            require_sequence_headroom(next_sequence, alternative.frames, other_frames)?;
        }
        Ok(())
    }

    /// Borrows every measured branch, including the independently funded ones.
    pub fn alternatives(&self) -> &[OriginalSourceMeasuredAlternativeV5] {
        &self.alternatives
    }

    /// Returns computed own debt DATA, or no future debt for a retired cold prefix.
    pub const fn remaining_request(&self) -> Option<NativeHeldCapacityRequestV3> {
        self.remaining
    }

    /// Returns separate componentwise normal and poison accounting envelopes.
    pub const fn envelopes(
        &self,
    ) -> (NativeHeldCapacityGeometryV3, NativeHeldCapacityGeometryV3) {
        (self.normal, self.poison)
    }

    /// Returns retained byte/entry growth including a tentative exact admission.
    pub const fn staged_coupled_peak(&self) -> (u64, u64) {
        (self.staged_peak_bytes, self.staged_peak_records)
    }

    /// Reports unresolved complete ordinary-floor association and co-settlement.
    pub const fn ordinary_association_required(&self) -> bool {
        self.ordinary_association_required
    }

    /// Reports unresolved original physical admission membership, not a receipt.
    pub const fn original_membership_required(&self) -> bool {
        self.original_membership_required
    }

    /// Returns complete other-floor record/begin/commit frame debt counted once.
    pub const fn other_sequence_frames(&self) -> u64 {
        self.other_frames
    }
}

impl OriginalSourceMeasuredAlternativeV5 {
    /// Returns the unchanged owner-only geometry from the common accumulator.
    pub const fn owner_geometry(&self) -> NativeHeldCapacityGeometryV3 {
        self.owner
    }

    /// Returns actual owner-plus-floor retained byte and entry growth.
    pub const fn coupled_peak(&self) -> (u64, u64) {
        (self.maximum_coupled_growth_bytes, self.maximum_coupled_growth_records)
    }

    /// Borrows ordered signed retained deltas including final floor deletion.
    pub fn coupled_prefixes(&self) -> impl Iterator<Item = (i128, i64)> + '_ {
        self.coupled
            .iter()
            .map(|prefix| (prefix.bytes, prefix.records))
    }

    /// Returns the widest key and actual framed record payload on this branch.
    pub const fn maximum_payload_widths(&self) -> (usize, usize) {
        (self.maximum_key_bytes, self.maximum_record_payload_bytes)
    }

    /// Returns remaining record frames plus two frames per transaction.
    pub const fn sequence_frames(&self) -> u64 {
        self.frames
    }

    /// Reports separately funded admission/current-cut prerequisites.
    pub const fn requires_independent_cut(&self) -> bool {
        self.independent_cut_required
    }

    /// Reports live original custody closure that this DATA cannot prove.
    pub const fn requires_original_custody(&self) -> bool {
        self.original_custody_required
    }
}

#[cfg(test)]
enum SourceMeasurementAppend {
    Original {
        transaction_id: [u8; 16],
        changes: Vec<NativeHeldCapacityChangeV3>,
        final_append: bool,
    },
}

#[cfg(test)]
impl SourceMeasurementAppend {
    fn measurement(&self) -> MeasurementAppend<'_> {
        match self {
            Self::Original {
                transaction_id,
                changes,
                final_append,
            } => MeasurementAppend {
                transaction_id: *transaction_id,
                changes,
                final_append: *final_append,
            },
        }
    }
}

// Compact images are only forecast DATA. Actual initial rows remain exact
// borrowed bytes; generated predecessors preserve the old marker byte identity.
#[derive(Clone, Copy)]
enum ForecastImage<'owner> {
    Actual(&'owner [u8]),
    Generated { prefix: [u8; 11], bytes: usize },
}

impl ForecastImage<'_> {
    fn image(&self) -> Result<NativeSuffixValueRef<'_>, JournalError> {
        match self {
            Self::Actual(bytes) => Ok(NativeSuffixValueRef::from_bytes(bytes)),
            Self::Generated { prefix, bytes } => NativeSuffixValueRef::zero_padded(prefix, *bytes)
                .map_err(super::native_suffix_error),
        }
    }
}

struct ForecastChange<'owner> {
    key: Vec<u8>,
    before: Option<ForecastImage<'owner>>,
    after: Option<ForecastImage<'owner>>,
}

impl<'owner> ForecastChange<'owner> {
    fn new(
        key: Vec<u8>,
        before: Option<ForecastImage<'owner>>,
        after: Option<ForecastImage<'owner>>,
    ) -> Result<Self, JournalError> {
        require_change_images(
            &key,
            before.as_ref().map(ForecastImage::image).transpose()?,
            after.as_ref().map(ForecastImage::image).transpose()?,
        )?;
        Ok(Self { key, before, after })
    }
}

struct ForecastAppend<'owner> {
    transaction_id: [u8; 16],
    changes: Vec<ForecastChange<'owner>>,
    final_append: bool,
}

impl ForecastAppend<'_> {
    fn measurement(&self) -> Result<MeasurementValueAppend<'_>, JournalError> {
        Ok(MeasurementValueAppend {
            transaction_id: self.transaction_id,
            changes: self
                .changes
                .iter()
                .map(|change| {
                    Ok(NativeBeforeAfterValueRef {
                        key: &change.key,
                        before: change
                            .before
                            .as_ref()
                            .map(ForecastImage::image)
                            .transpose()?,
                        after: change
                            .after
                            .as_ref()
                            .map(ForecastImage::image)
                            .transpose()?,
                    })
                })
                .collect::<Result<Vec<_>, JournalError>>()?,
            final_append: self.final_append,
        })
    }
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn measure_remaining(
    typed_own_source: &OriginalSourceCapacityRecordV5,
    continuation: &OriginalSourceContinuationDataV5,
    owners: &OwnerView<'_>,
    limits: JournalLimits,
    floor_present: bool,
) -> Result<OriginalSourceGeometryDataV5, JournalError> {
    if typed_own_source.original_provenance() != continuation.provenance() {
        return Err(invalid("original Source geometry provenance changed"));
    }
    validate_original_bindings(typed_own_source, continuation)?;
    validate_cold_capsule(typed_own_source, continuation)?;
    let floor = typed_own_source.to_journal_record()?;
    let floor_width = floor.value().ok_or(JournalError::InvalidTransaction)?.len();
    let mut result = measure_envelopes(
        continuation, owners, limits, floor.key().len(), floor_width, floor_present,
    )?;
    let normal = result.normal;
    let poison = result.poison;
    let transactions = normal.transactions.max(poison.transactions);
    result.remaining = if transactions == 0 {
        None
    } else {
        let mut request = typed_own_source.request();
        request.future_transactions = transactions;
        request.terminal_records = normal.records;
        request.terminal_bytes = normal.append_bytes;
        request.poison_records = poison.records;
        request.poison_bytes = poison.append_bytes;
        require_own_debt(typed_own_source.request(), request)?;
        // The same constructor retains immutable origin, admission and bindings.
        OriginalSourceCapacityRecordV5::new(
            request,
            typed_own_source.admission_transaction_id(),
            typed_own_source.origin_budgets(),
            typed_own_source.original_provenance().clone(),
        )?;
        if continuation.prefix() == OriginalSourceContinuationPrefixV5::Applying
            && typed_own_source.request() != request
        {
            return Err(invalid("original Source initial envelope differs from complete geometry"));
        }
        Some(request)
    };
    Ok(result)
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn measure_envelopes(
    continuation: &OriginalSourceContinuationDataV5,
    owners: &OwnerView<'_>,
    limits: JournalLimits,
    floor_key_width: usize,
    floor_width: usize,
    floor_present: bool,
) -> Result<OriginalSourceGeometryDataV5, JournalError> {
    let mut alternatives = Vec::new();
    let mut normal = NativeHeldCapacityGeometryV3::default();
    let mut poison = NativeHeldCapacityGeometryV3::default();
    let mut staged_peak_bytes = 0;
    let mut staged_peak_records = 0;

    for alternative in continuation.alternatives() {
        let appends = materialize_templates(alternative, owners, floor_width)?;
        let measurements = appends
            .iter()
            .map(ForecastAppend::measurement)
            .collect::<Result<Vec<_>, _>>()?;
        let measured = measure_value_appends_with_prefixes(
            NativeHeldCapacityPurposeV3::Provider,
            measurements,
            limits,
            floor_width,
        )?;
        let measured = coupled_measurement(
            measured,
            alternative,
            floor_key_width,
            floor_width,
            floor_present,
        )?;
        staged_peak_bytes = staged_peak_bytes.max(positive_bytes(i128::from(
            measured.maximum_coupled_growth_bytes,
        ))?);
        staged_peak_records = staged_peak_records.max(positive_records(
            measured.maximum_coupled_growth_records as i64,
        )?);

        if measured.poison {
            fold_envelope(&mut poison, measured.owner);
        } else {
            fold_envelope(&mut normal, measured.owner);
        }
        alternatives.push(measured);
    }
    if normal.transactions == 0 {
        normal = poison;
    }
    if poison.transactions == 0 {
        poison = normal;
    }

    Ok(OriginalSourceGeometryDataV5 {
        alternatives,
        normal,
        poison,
        remaining: None,
        staged_peak_bytes,
        staged_peak_records,
        other_frames: 0,
        ordinary_association_required: true,
        original_membership_required: true,
    })
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn validate_original_bindings(
    floor: &OriginalSourceCapacityRecordV5,
    data: &OriginalSourceContinuationDataV5,
) -> Result<(), JournalError> {
    if let Some(original) = data.original() {
        let request = floor.request();
        if request.owner_digest != *original.reservation_acquisition_digest.as_bytes()
            || request.operation_id != original.operation_id
            || request.artifact_digest != *original.attempt_digest.as_bytes()
            || request.checkpoint_digest != *original.root_request_digest.as_bytes()
            || request.chain_head_digest != *original.session_binding.as_bytes()
        {
            return Err(invalid("original Source geometry immutable owner bindings"));
        }
    }
    Ok(())
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn validate_cold_capsule(
    floor: &OriginalSourceCapacityRecordV5,
    data: &OriginalSourceContinuationDataV5,
) -> Result<(), JournalError> {
    let Some(archive) = data.cold_archive() else {
        return Ok(());
    };
    let mut original_request = floor.request();
    let origin = floor.origin_budgets();
    original_request.future_transactions = 20;
    original_request.terminal_records = origin.terminal_records;
    original_request.terminal_bytes = origin.terminal_bytes;
    original_request.poison_records = origin.poison_records;
    original_request.poison_bytes = origin.poison_bytes;
    let original = OriginalSourceCapacityRecordV5::new(
        original_request,
        floor.admission_transaction_id(),
        origin,
        floor.original_provenance().clone(),
    )?;
    let record = original.to_journal_record()?;
    let decoded = OriginalSourceCapacityRecordV5::decode(
        record.key(),
        archive.initial_source_floor_bytes(),
    )?;
    if decoded != original || record.value() != Some(archive.initial_source_floor_bytes())
        || archive.prepared().claims().original_source_floor.as_bytes() != &original.reservation_id()
        || archive.prepared().claims().admission_transaction != original.admission_transaction_id()
    {
        return Err(invalid("original Source cold copied initial floor differs"));
    }
    Ok(())
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
fn materialize_templates<'owner>(
    alternative: &OriginalSourceContinuationAlternativeV5,
    owners: &OwnerView<'owner>,
    floor_width: usize,
) -> Result<Vec<ForecastAppend<'owner>>, JournalError> {
    let mut states = BTreeMap::<Vec<u8>, (usize, ForecastImage<'owner>)>::new();
    let mut appends = Vec::new();
    for (index, edge) in alternative.edges().iter().enumerate() {
        let mut changes = Vec::new();
        for (value_index, value) in edge.values().iter().enumerate() {
            let previous = states.get(value.key());
            let before = match value.before_dependency() {
                OriginalSourceBeforeDependencyV5::ActualGraph => {
                    if previous.is_some() {
                        return Err(invalid("original Source repeated first before dependency"));
                    }
                    owners.get(value.key()).copied().map(ForecastImage::Actual)
                }
                OriginalSourceBeforeDependencyV5::PreviousOutput(predecessor) => {
                    let (actual, bytes) = previous
                        .ok_or(invalid("original Source forecast predecessor absent"))?;
                    if *actual != predecessor {
                        return Err(invalid("original Source forecast predecessor changed"));
                    }
                    Some(*bytes)
                }
                OriginalSourceBeforeDependencyV5::IndependentlyFundedCut => {
                    // No independently admitted row is invented. The baseline
                    // is actual absence/value or this branch's prior output;
                    // concrete funding must reacquire the full current cut.
                    previous
                        .map(|(_, bytes)| *bytes)
                        .or_else(|| owners.get(value.key()).copied().map(ForecastImage::Actual))
                }
            };
            let width = value
                .maximum_value_bytes()
                .checked_add(if value.requires_source_floor_width() {
                    floor_width
                } else {
                    0
                })
                .ok_or(JournalError::JournalTooLarge)?;
            let after = forecast_image(width, index, value_index)?;
            changes.push(ForecastChange::new(
                value.key().to_vec(),
                before,
                Some(after),
            )?);
            states.insert(value.key().to_vec(), (index, after));
        }
        let transaction_id = template_transaction_id(index)?;
        let provider_step = match edge.kind() {
            OriginalSourceContinuationKindV5::Held(step) => Some(capacity_step(step)?),
            OriginalSourceContinuationKindV5::Cleanup(_) => {
                Some(NativeHeldCapacityStepV3::ProviderLifecycleCleanup)
            }
            OriginalSourceContinuationKindV5::FirstRequested
            | OriginalSourceContinuationKindV5::PreRequestedCold(_) => None,
        };
        let final_append = if let Some(step) = provider_step {
            let shape = changes
                .iter()
                .map(|change| ChangeShape {
                    key: &change.key,
                    before_present: change.before.is_some(),
                    after_present: change.after.is_some(),
                })
                .collect::<Vec<_>>();
            super::v2::require_provider_shape(step, transaction_id, &shape)?;
            step.is_final()
        } else {
            edge.is_final()
        };
        let append = ForecastAppend {
            transaction_id,
            changes,
            final_append,
        };
        appends.push(append);
    }
    Ok(appends)
}

fn forecast_image(
    width: usize,
    edge: usize,
    value: usize,
) -> Result<ForecastImage<'static>, JournalError> {
    if width < 11 {
        return Err(invalid("original Source forecast value bound"));
    }
    let mut prefix = [0; 11];
    prefix[0] = 0xfc;
    prefix[1..9].copy_from_slice(&(edge as u64).to_be_bytes());
    prefix[9..11].copy_from_slice(
        &u16::try_from(value)
            .map_err(|_| JournalError::InvalidTransaction)?
            .to_be_bytes(),
    );
    Ok(ForecastImage::Generated {
        prefix,
        bytes: width,
    })
}

// The former byte materializer remains only as a small-vector test oracle.
#[cfg(test)]
fn forecast_marker(width: usize, edge: usize, value: usize) -> Result<Vec<u8>, JournalError> {
    if width < 11 {
        return Err(invalid("original Source forecast value bound"));
    }

    let mut bytes = vec![0; width];
    bytes[0] = 0xfc; // Every real canonical owner value starts with AOSSPL01.
    bytes[1..9].copy_from_slice(&(edge as u64).to_be_bytes());
    bytes[9..11].copy_from_slice(
        &u16::try_from(value)
            .map_err(|_| JournalError::InvalidTransaction)?
            .to_be_bytes(),
    );
    Ok(bytes)
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn template_transaction_id(index: usize) -> Result<[u8; 16], JournalError> {
    let mut id = [0xfe; 16];
    id[8..].copy_from_slice(
        &u64::try_from(index)
            .map_err(|_| JournalError::InvalidTransaction)?
            .checked_add(1)
            .ok_or(JournalError::InvalidTransaction)?
            .to_be_bytes(),
    );
    Ok(id)
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn coupled_prefixes(
    measured: &MeasuredAppends,
    floor_key_width: usize,
    floor_width: usize,
    floor_present: bool,
) -> Result<(Vec<CoupledPrefix>, u64, u64), JournalError> {
    let floor_bytes = add(floor_key_width as u64, floor_width as u64)?;
    let mut coupled = Vec::new();
    let mut maximum_coupled_growth_bytes = 0;
    let mut maximum_coupled_growth_records = 0;
    for prefix in &measured.prefixes {
        let removed = floor_present && prefix.final_append;
        let prefix = CoupledPrefix {
            bytes: prefix.owner_bytes
                - if removed { i128::from(floor_bytes) } else { 0 },
            records: prefix.owner_records - i64::from(removed),
        };
        maximum_coupled_growth_bytes =
            maximum_coupled_growth_bytes.max(positive_bytes(prefix.bytes)?);
        maximum_coupled_growth_records =
            maximum_coupled_growth_records.max(positive_records(prefix.records)?);
        coupled.push(prefix);
    }
    Ok((
        coupled,
        maximum_coupled_growth_bytes,
        maximum_coupled_growth_records,
    ))
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn coupled_measurement(
    measured: MeasuredAppends,
    alternative: &OriginalSourceContinuationAlternativeV5,
    floor_key_width: usize,
    floor_width: usize,
    floor_present: bool,
) -> Result<OriginalSourceMeasuredAlternativeV5, JournalError> {
    let (coupled, maximum_coupled_growth_bytes, maximum_coupled_growth_records) =
        coupled_prefixes(&measured, floor_key_width, floor_width, floor_present)?;
    Ok(OriginalSourceMeasuredAlternativeV5 {
        frames: transaction_frames(
            u64::from(measured.geometry.records),
            u64::from(measured.geometry.transactions),
        )?,
        owner: measured.geometry,
        coupled,
        maximum_coupled_growth_bytes,
        maximum_coupled_growth_records,
        maximum_key_bytes: measured.maximum_key_bytes,
        maximum_record_payload_bytes: measured.maximum_record_payload_bytes,
        poison: alternative.is_poison(),
        independent_cut_required: alternative
            .edges()
            .iter()
            .any(|edge| edge.requires_independent_cut()),
        original_custody_required: alternative
            .edges()
            .iter()
            .any(|edge| edge.requires_original_custody_closure()),
    })
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn fold_envelope(target: &mut NativeHeldCapacityGeometryV3, geometry: NativeHeldCapacityGeometryV3) {
    target.transactions = target.transactions.max(geometry.transactions);
    target.records = target.records.max(geometry.records);
    target.append_bytes = target.append_bytes.max(geometry.append_bytes);
    target.maximum_transaction_records = target
        .maximum_transaction_records
        .max(geometry.maximum_transaction_records);
    target.maximum_transaction_record_bytes = target
        .maximum_transaction_record_bytes
        .max(geometry.maximum_transaction_record_bytes);
    target.maximum_retained_growth_bytes = target
        .maximum_retained_growth_bytes
        .max(geometry.maximum_retained_growth_bytes);
    target.maximum_retained_growth_records = target
        .maximum_retained_growth_records
        .max(geometry.maximum_retained_growth_records);
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn require_own_debt(
    old: NativeHeldCapacityRequestV3,
    next: NativeHeldCapacityRequestV3,
) -> Result<(), JournalError> {
    if next.future_transactions > old.future_transactions
        || next.terminal_records > old.terminal_records
        || next.terminal_bytes > old.terminal_bytes
        || next.poison_records > old.poison_records
        || next.poison_bytes > old.poison_bytes
    {
        return Err(JournalError::LimitExceeded(
            "original Source complete own-floor geometry",
        ));
    }
    Ok(())
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn require_coupled_headroom(
    limits: JournalLimits,
    usage: NativeHeldCapacityUsageV3,
    measured: &OriginalSourceMeasuredAlternativeV5,
) -> Result<(), JournalError> {
    if add(
        add(usage.materialized_bytes, usage.reserved_bytes)?,
        measured.maximum_coupled_growth_bytes,
    )? > limits.maximum_materialized_bytes as u64
        || add(
            add(usage.materialized_records, usage.reserved_records)?,
            measured.maximum_coupled_growth_records,
        )? > limits.maximum_materialized_records as u64
    {
        return Err(JournalError::LimitExceeded("original Source coupled retained peak"));
    }
    Ok(())
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn transaction_frames(records: u64, transactions: u64) -> Result<u64, JournalError> {
    add(
        records,
        transactions
            .checked_mul(2)
            .ok_or(JournalError::SequenceExhausted)?,
    )
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn require_sequence_headroom(
    next_sequence: u64,
    own_frames: u64,
    other_frames: u64,
) -> Result<(), JournalError> {
    next_sequence
        .checked_add(own_frames)
        .and_then(|next| next.checked_add(other_frames))
        .ok_or(JournalError::SequenceExhausted)?;
    Ok(())
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn positive_bytes(value: i128) -> Result<u64, JournalError> {
    u64::try_from(value.max(0)).map_err(|_| JournalError::JournalTooLarge)
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn positive_records(value: i64) -> Result<u64, JournalError> {
    u64::try_from(value.max(0))
        .map_err(|_| JournalError::LimitExceeded("original Source retained entries"))
}

#[doc(hidden)]
/// Runs the existing bounded historical DATA calculation.
///
/// # Errors
/// Returns the original malformed or exhausted DATA classification.
pub fn capacity_step(step: SourceStep) -> Result<NativeHeldCapacityStepV3, JournalError> {
    use NativeHeldCapacityStepV3 as Capacity;
    Ok(match step {
        SourceStep::ChallengeIssued => Capacity::ProviderChallengeIssued,
        SourceStep::StoragePrepared => Capacity::ProviderStoragePrepared,
        SourceStep::ChallengeSpent => Capacity::ProviderChallengeSpent,
        SourceStep::CompletionCommitted => Capacity::ProviderSixRowComplete,
        SourceStep::HeldPrepared => Capacity::ProviderHeldPrepared,
        SourceStep::HeldStored => Capacity::ProviderHeldStored,
        SourceStep::RootDispositionPrepared => Capacity::ProviderRootDispositionPrepared,
        SourceStep::RelayStored => Capacity::ProviderRelayStored,
        SourceStep::StorageSettlementRecorded => Capacity::ProviderStorageSettlement,
        SourceStep::ProviderSettledPrepared => Capacity::ProviderSettledPrepared,
        SourceStep::ProviderSettledStored => Capacity::ProviderSettledStored,
        SourceStep::RootRecoveryRecorded => Capacity::ProviderRootRecoveryStored,
        SourceStep::StorageRecoveryPrepared => Capacity::ProviderRecoveryRelayPrepared,
        SourceStep::StorageRecoveryQueryStored => Capacity::ProviderRecoveryRelayStored,
        SourceStep::StorageRecoveryRecorded => Capacity::ProviderStorageRecoveryStored,
        SourceStep::ProviderRecoveryPrepared => Capacity::ProviderRecoveryTerminalPrepared,
        SourceStep::ProviderRecoveryStored => Capacity::ProviderRecoveryTerminalStored,
        SourceStep::RootTerminalRecorded => Capacity::ProviderRootTerminalStored,
        SourceStep::Requested => {
            return Err(invalid("original Source initial Requested uses distinct framing"));
        }
    })
}



#[cfg(test)]
#[path = "original_source/tests.rs"]
mod tests;
