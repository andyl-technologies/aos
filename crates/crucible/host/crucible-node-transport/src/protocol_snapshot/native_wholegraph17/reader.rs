//! Retains immutable evidence and current modeled custody in one once owner.

mod capture;
mod historical;
mod launch;

use super::{
    BorrowedNativeCurrentGraph17Plan, NativeCurrentGraph17ReadLimits,
    NativeCurrentGraph17RootSpans, borrowed::SelectedControl17Pass, hello::NativeHello17Data,
};
use crate::ProviderError;
use crate::handshake::HistoricalAuthority17;
use crate::protocol_snapshot::owned11::typed::{Fields, Native17Build, invalid};
use crate::protocol_snapshot::restored_settled17::cold_admission::NativeCold17GraphAdmission;
use crate::protocol_snapshot::restored_settled17::{
    aliases::RestoredSettledNative17AliasSummary,
    current_lineage17::{
        CurrentNativeLineage17Data, CurrentNativeLineage17ReadAttempt,
        NativeMappingNormalization17, NativeMappingNormalization17ReadAttempt,
    },
    historical_auth::HistoricalRestorationStages17,
};
use crate::reference_packet::{
    continuation_models::settled_reader::PacketSettledModel17Data,
    control::{CurrentControl17Data, CurrentControl17ReadAttempt},
};
use crate::retained_metadata::{
    MetadataObserver, records::ValidatedMetadataRecords, requested_metadata_backing_storage_data,
};
use crucible_node_format::{ExtensionSelection, U64};
use std::mem::size_of;
use std::sync::Arc;

/// Owns current operational Control/model and the complete immutable wire.
///
/// Private flags become complete only after the whole known-field/alias pass,
/// borrowed component correspondence, exact target preflight, construction and
/// current Control conjunction. This DATA cannot create a live native grant.
pub(crate) struct NativeCurrentGraph17Data {
    raw: Vec<u8>,
    summaries: Vec<RestoredSettledNative17AliasSummary>,
    control: CurrentControl17Data,
    lineage: CurrentNativeLineage17Data,
    authority: HistoricalAuthority17,
    normalization: NativeMappingNormalization17,
    hello: NativeHello17Data,
    creator: u32,
    selected_target_requested: usize,
}

/// Retains completed children while transferring them into their final owner.
#[derive(Default)]
struct NativeCurrentGraph17Promotion {
    control: Option<CurrentControl17Data>,
    lineage: Option<CurrentNativeLineage17Data>,
    authority: Option<HistoricalAuthority17>,
    normalization: Option<NativeMappingNormalization17>,
}

/// Keeps every actual backing allocation after any intermediate read failure.
#[derive(Default)]
pub(crate) struct NativeCurrentGraph17DecodeAttempt {
    started: bool,
    failed: bool,
    raw: Vec<u8>,
    summaries: Vec<RestoredSettledNative17AliasSummary>,
    control: CurrentControl17ReadAttempt,
    lineage: CurrentNativeLineage17ReadAttempt,
    authority: <HistoricalAuthority17 as Native17Build>::Attempt,
    normalization: NativeMappingNormalization17ReadAttempt,
    hello: NativeHello17Data,
    target_groups: Vec<bool>,
    selected_groups: Vec<Option<Arc<[ExtensionSelection]>>>,
    completed: Option<NativeCurrentGraph17Data>,
    promotion: NativeCurrentGraph17Promotion,
    maximum_requested: usize,
    preflight_requested: Option<usize>,
    constructed_requested: Option<usize>,
}

/// Installs the actual partial owner before its first raw-bank reservation.
///
/// Callers with independently admitted parser axes use the explicit-limits
/// variant. The backing ceiling includes this child's raw duplicate and alias
/// scratch; the enclosing owner already contains this child's inline header.
///
/// # Errors
/// Refuses owner reuse, allocation failure, budget exhaustion or any complete
/// source, alias, logical-custody or current Control/model disagreement.
pub(crate) fn read_native_current_graph17_into_data(
    input: &[u8],
    destination: &mut Option<NativeCurrentGraph17DecodeAttempt>,
    maximum_requested: usize,
) -> Result<(), ProviderError> {
    read_native_current_graph17_with_limits_into_data(
        input,
        destination,
        NativeCurrentGraph17ReadLimits {
            maximum_requested,
            maximum_target_requested: maximum_requested,
            maximum_nodes: input.len().max(1),
            maximum_depth: 64,
        },
    )
}

/// Reads under exact independently admitted backing, node and depth ceilings.
///
/// # Errors
/// Refuses the same failures as the default reader and any explicit parser-axis
/// exhaustion. A failed destination retains every successful reservation/child.
pub(crate) fn read_native_current_graph17_with_limits_into_data(
    input: &[u8],
    destination: &mut Option<NativeCurrentGraph17DecodeAttempt>,
    limits: NativeCurrentGraph17ReadLimits,
) -> Result<(), ProviderError> {
    read_native_current_graph17_with_admission_into_data(input, destination, limits, None)
}

pub(crate) fn read_native_current_graph17_with_admission_into_data(
    input: &[u8],
    destination: &mut Option<NativeCurrentGraph17DecodeAttempt>,
    limits: NativeCurrentGraph17ReadLimits,
    admission: Option<&NativeCold17GraphAdmission<'_, '_>>,
) -> Result<(), ProviderError> {
    if destination.is_some() {
        return Err(invalid());
    }

    *destination = Some(NativeCurrentGraph17DecodeAttempt::default());
    let owner = destination.as_mut().ok_or_else(invalid)?;
    owner.started = true;
    owner.failed = true;
    owner.maximum_requested = limits.maximum_requested;
    if input.len() > limits.maximum_requested {
        return Err(invalid());
    }

    reserve_exact(&mut owner.raw, input.len())?;
    owner.raw.extend_from_slice(input);
    limits.authenticate_wire_data(&owner.raw)?;

    let roots = NativeCurrentGraph17RootSpans::read(&owner.raw)?;
    let records = ValidatedMetadataRecords::validate(roots.records, 131072, usize::MAX)?;
    let alias_rows = count_alias_rows(roots.aliases, records.row_count())?;
    let scratch = size_of::<RestoredSettledNative17AliasSummary>()
        .checked_add(size_of::<bool>())
        .and_then(|bytes| bytes.checked_add(size_of::<Option<Arc<[ExtensionSelection]>>>()))
        .and_then(|bytes| bytes.checked_mul(alias_rows))
        .and_then(|bytes| bytes.checked_add(owner.raw.capacity()))
        .ok_or_else(invalid)?;
    let remaining = limits
        .maximum_requested
        .checked_sub(scratch)
        .ok_or_else(invalid)?;

    reserve_exact(&mut owner.summaries, alias_rows)?;
    owner.summaries.resize_with(alias_rows, Default::default);
    reserve_exact(&mut owner.target_groups, alias_rows)?;
    owner.target_groups.resize(alias_rows, false);
    reserve_exact(&mut owner.selected_groups, alias_rows)?;
    owner.selected_groups.resize_with(alias_rows, || None);

    if let Some(admission) = admission {
        admission.finish_data(
            admission.banks,
            owner.retained_requested_storage_data(limits.maximum_requested)?,
        )?;
        admission.boundary.begin_data(
            admission.targets,
            0,
            crate::protocol_snapshot::restored_settled17::restored_settled_native17_counter_scratch_data(),
        )?;
    }

    let selected_limits = NativeCurrentGraph17ReadLimits {
        maximum_requested: remaining,
        ..limits
    };
    let creator;
    {
        let mut plan = BorrowedNativeCurrentGraph17Plan::validate_with_limits_data(
            &owner.raw,
            selected_limits,
            &mut owner.summaries,
        )?;
        creator = plan.creator_data();
        let requested = plan.replay_selected_control17_data(
            selected_limits,
            SelectedControl17Pass::Preflight,
            &mut owner.target_groups,
            &mut owner.selected_groups,
        )?;
        owner.preflight_requested = Some(requested);
        if let Some(admission) = admission {
            admission.boundary.construct_data(
                admission.targets,
                requested,
                0,
                crate::protocol_snapshot::restored_settled17::restored_settled_native17_counter_scratch_data(),
            )?;
        }
        owner.target_groups.fill(false);
        let constructed = plan.replay_selected_control17_data(
            selected_limits,
            SelectedControl17Pass::Build(
                &mut owner.control,
                &mut owner.lineage,
                &mut owner.authority,
                &mut owner.normalization,
                &mut owner.hello,
            ),
            &mut owner.target_groups,
            &mut owner.selected_groups,
        )?;
        owner.constructed_requested = Some(constructed);
        if constructed != requested {
            return Err(invalid());
        }
    }

    let control = owner.control.completed_data().ok_or_else(invalid)?;
    control.authenticate_local_groups_data()?;
    control.model_data().ok_or_else(invalid)?;
    owner.retained_requested_storage_data(limits.maximum_requested)?;
    let selected_target_requested = owner.preflight_requested.ok_or_else(invalid)?;
    if selected_target_requested > limits.maximum_target_requested {
        return Err(invalid());
    }

    // Each fallible transfer lands in a slot of the caller-owned attempt before
    // another transfer can fail. Raw banks stay in place until all slots exist.
    owner.promotion.control = owner.control.take_completed_data();
    owner.promotion.control.as_ref().ok_or_else(invalid)?;
    owner.promotion.lineage = Some(owner.lineage.take_completed_data()?);
    owner.promotion.authority = HistoricalAuthority17::take_output_data(&mut owner.authority);
    owner.promotion.authority.as_ref().ok_or_else(invalid)?;
    owner.promotion.normalization =
        NativeMappingNormalization17::take_output_data(&mut owner.normalization);
    owner.promotion.normalization.as_ref().ok_or_else(invalid)?;
    match (
        owner.promotion.control.take(),
        owner.promotion.lineage.take(),
        owner.promotion.authority.take(),
        owner.promotion.normalization.take(),
    ) {
        (Some(control), Some(lineage), Some(authority), Some(normalization)) => {
            owner.completed = Some(NativeCurrentGraph17Data {
                raw: std::mem::take(&mut owner.raw),
                summaries: std::mem::take(&mut owner.summaries),
                control,
                lineage,
                authority,
                normalization,
                hello: std::mem::take(&mut owner.hello),
                creator,
                selected_target_requested,
            });
        }
        (control, lineage, authority, normalization) => {
            owner.promotion.control = control;
            owner.promotion.lineage = lineage;
            owner.promotion.authority = authority;
            owner.promotion.normalization = normalization;
            return Err(invalid());
        }
    }

    owner
        .completed
        .as_ref()
        .ok_or_else(invalid)?
        .validate_data()?;
    owner.failed = false;
    owner.validate_data()?;
    if let Some(admission) = admission {
        admission.finish_data(
            admission.targets,
            owner.retained_requested_storage_data(limits.maximum_requested)?,
        )?;
    }
    Ok(())
}

/// Quotes the actual raw and alias-bank layouts before their first reservation.
pub(crate) fn native_current_graph17_banks_data(
    input: &[u8],
    limits: NativeCurrentGraph17ReadLimits,
) -> Result<usize, ProviderError> {
    limits.authenticate_wire_data(input)?;
    let roots = NativeCurrentGraph17RootSpans::read(input)?;
    let records = ValidatedMetadataRecords::validate(roots.records, 131072, usize::MAX)?;
    let aliases = count_alias_rows(roots.aliases, records.row_count())?;
    let element = size_of::<RestoredSettledNative17AliasSummary>()
        .checked_add(size_of::<bool>())
        .and_then(|bytes| bytes.checked_add(size_of::<Option<Arc<[ExtensionSelection]>>>()))
        .ok_or_else(invalid)?;
    input
        .len()
        .checked_add(aliases.checked_mul(element).ok_or_else(invalid)?)
        .ok_or_else(invalid)
}

impl NativeCurrentGraph17DecodeAttempt {
    /// Borrows the narrow result only after every selected read phase succeeded.
    pub(crate) fn completed_data(&self) -> Option<&NativeCurrentGraph17Data> {
        if self.failed {
            None
        } else {
            self.completed.as_ref()
        }
    }

    /// Checks complete selected reconstruction without promoting Source ancestry.
    ///
    /// # Errors
    /// Refuses any incomplete/failed attempt or invalid current Control/model.
    pub(crate) fn validate_data(&self) -> Result<(), ProviderError> {
        self.completed_data().ok_or_else(invalid)?.validate_data()
    }

    /// Counts actual retained backing, excluding its already embedded header.
    ///
    /// # Errors
    /// Refuses overflow, malformed retained storage or excess remaining credit.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        observer.vector::<u8>(self.raw.capacity())?;
        observer.vector::<RestoredSettledNative17AliasSummary>(self.summaries.capacity())?;
        self.control.observe_attempt_data(&mut observer)?;
        self.lineage.observe_attempt_data(&mut observer)?;
        HistoricalAuthority17::observe_attempt_data(&self.authority, &mut observer)?;
        NativeMappingNormalization17::observe_attempt_data(&self.normalization, &mut observer)?;
        self.hello.observe_data(&mut observer)?;
        observer.vector::<bool>(self.target_groups.capacity())?;
        observer.vector::<Option<Arc<[ExtensionSelection]>>>(self.selected_groups.capacity())?;
        if let Some(value) = &self.promotion.control {
            value.observe_owned_metadata_data(&mut observer)?;
        }
        if let Some(value) = &self.promotion.lineage {
            value.observe_metadata_data(&mut observer)?;
        }
        if let Some(value) = &self.promotion.authority {
            HistoricalAuthority17::observe_output_data(value, &mut observer)?;
        }
        if let Some(value) = &self.promotion.normalization {
            NativeMappingNormalization17::observe_output_data(value, &mut observer)?;
        }
        if let Some(value) = &self.completed {
            observer.vector::<u8>(value.raw.capacity())?;
            observer.vector::<RestoredSettledNative17AliasSummary>(value.summaries.capacity())?;
            value.control.observe_owned_metadata_data(&mut observer)?;
            value.lineage.observe_metadata_data(&mut observer)?;
            HistoricalAuthority17::observe_output_data(&value.authority, &mut observer)?;
            NativeMappingNormalization17::observe_output_data(&value.normalization, &mut observer)?;
            value.hello.observe_data(&mut observer)?;
        }
        let mut selected = 0usize;
        for values in self.selected_groups.iter().flatten() {
            let (layout, _) = std::alloc::Layout::new::<[usize; 2]>()
                .extend(
                    std::alloc::Layout::array::<ExtensionSelection>(values.len())
                        .map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?;
            selected = selected
                .checked_add(layout.pad_to_align().size())
                .ok_or_else(invalid)?;
            for value in values.as_ref() {
                ExtensionSelection::observe_output_data(value, &mut observer)?;
            }
        }
        let requested = requested_metadata_backing_storage_data(&observer.finish())?
            .checked_add(selected)
            .ok_or_else(invalid)?;
        if requested > maximum {
            return Err(invalid());
        }
        Ok(requested)
    }

    /// Reports the inline layout embedded by the enclosing output once owner.
    pub(crate) const fn inline_header_bytes_data() -> usize {
        size_of::<Self>()
    }
}

impl NativeCurrentGraph17Data {
    /// Checks the operational model without manufacturing imported host owners.
    ///
    /// # Errors
    /// Refuses partial data, an absent sealed identity or invalid current model.
    pub(crate) fn validate_data(&self) -> Result<(), ProviderError> {
        if self.creator == 0 || self.control.historical_creator_data() != self.creator {
            return Err(invalid());
        }
        self.control.authenticate_local_groups_data()?;
        self.control.model_data().ok_or_else(invalid)?;
        Ok(())
    }

    /// Returns the actual negotiated frame limit from the retained authority.
    ///
    /// # Errors
    /// Refuses invalid operational data or a frame limit outside this platform.
    pub(crate) fn maximum_frame_bytes_data(&self) -> Result<usize, ProviderError> {
        self.validate_data()?;
        usize::try_from(self.authority.data.limits.frame_bytes.get()).map_err(|_| invalid())
    }

    /// Borrows the exact complete raw graph owned by this once decoder.
    ///
    /// # Errors
    /// Refuses incomplete current modeled state or a failed final conjunction.
    pub(crate) fn raw_current_graph17_data(&self) -> Result<&[u8], ProviderError> {
        self.validate_data()?;
        Ok(&self.raw)
    }

    /// Borrows the actual retained Commit Hold DATA used by historical proofs.
    ///
    /// # Errors
    /// Refuses incomplete data or an absent actual Commit Hold slot.
    pub(crate) fn restoration_hold_data(
        &self,
    ) -> Result<
        &crate::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
        ProviderError,
    > {
        self.validate_data()?;
        Ok(&self
            .lineage
            .commit_data()
            .hold
            .value_data()?
            .as_ref()
            .ok_or_else(invalid)?
            .0)
    }

    /// Borrows this exact native reserve's original-spend ledger as read-only DATA.
    ///
    /// # Errors
    /// Refuses incomplete native operational data.
    pub(crate) fn archived_spend_ledger_data(
        &self,
    ) -> Result<
        &crate::protocol_snapshot::restored_suffix_history::HistoricalRestoredSuffixLedger,
        ProviderError,
    > {
        self.validate_data()?;
        Ok(&self.lineage.reserve_ledger)
    }

    /// Reborrows roots only from this complete retained whole-wire owner.
    ///
    /// # Errors
    /// Refuses incomplete operational data or changed closed outer framing.
    pub(crate) fn raw_root_spans_data(
        &self,
    ) -> Result<NativeCurrentGraph17RootSpans<'_>, ProviderError> {
        self.validate_data()?;
        NativeCurrentGraph17RootSpans::read(&self.raw)
    }

    /// Reports actual preflight/construction-equivalent selected typed demand.
    ///
    /// Raw and alias/cache banks are separate backing terms; this scalar conveys
    /// no native allowance, imported owner or live action authorization.
    pub(crate) fn selected_target_requested_storage_data(&self) -> usize {
        self.selected_target_requested
    }

    /// Returns the actual original creator scalar from the authenticated root pass.
    pub(crate) fn creator_data(&self) -> u32 {
        self.creator
    }

    /// Borrows the actual complete current operational Control cache.
    pub(crate) fn current_control_data(&self) -> &CurrentControl17Data {
        &self.control
    }

    /// Borrows the complete current modeled queues and logical once custody.
    ///
    /// # Errors
    /// Refuses incomplete data or a restoration-in-progress program.
    pub(crate) fn current_model17_data(&self) -> Result<&PacketSettledModel17Data, ProviderError> {
        self.validate_data()?;
        self.control.model_data().ok_or_else(invalid)
    }

    /// Borrows only the historical verification key retained from the actual Boot.
    ///
    /// # Errors
    /// Refuses incomplete data or an absent exact32-byte historical key.
    pub(crate) fn historical_private_key17_data(&self) -> Result<&[u8; 32], ProviderError> {
        self.validate_data()?;
        Ok(self.lineage.private_key_data())
    }

    /// Returns the actual same-pass Boot role without a live issuer.
    pub(crate) fn current_boot_group_data(&self) -> usize {
        self.lineage.boot_group_data()
    }

    /// Borrows the exact three signed stages consumed by historical verification.
    ///
    /// # Errors
    /// Refuses incomplete signed Arm, World or first-observation cache fields.
    pub(crate) fn restoration_stages17_data(
        &self,
    ) -> Result<HistoricalRestorationStages17<'_>, ProviderError> {
        self.validate_data()?;
        self.lineage.restoration_stages17_data()
    }

    /// Borrows the narrowly retained signed lineage and logical spend ledger.
    pub(crate) fn current_lineage17_data(&self) -> &CurrentNativeLineage17Data {
        &self.lineage
    }

    /// Returns the real sealed suffix's admitted original count.
    ///
    /// # Errors
    /// Refuses partial data or absent/unverified/mismatched sealed suffix facts.
    pub(crate) fn restored_suffix_maximum_originals_data(&self) -> Result<U64, ProviderError> {
        self.validate_data()?;
        Ok(self.lineage.restored_suffix_maximum_originals_data())
    }
}

fn reserve_exact<T>(values: &mut Vec<T>, capacity: usize) -> Result<(), ProviderError> {
    if !values.is_empty() || values.capacity() != 0 {
        return Err(invalid());
    }
    values.try_reserve_exact(capacity).map_err(|_| invalid())?;
    if values.capacity() != capacity {
        return Err(invalid());
    }
    Ok(())
}

fn count_alias_rows(input: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut count = 0usize;
    while fields.next()?.is_some() {
        count = count.checked_add(1).ok_or_else(invalid)?;
        if count > maximum {
            return Err(invalid());
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prospective_raw_alias_banks_match_real_failed_partial_backing() {
        for count in [0, 1, 3] {
            let mut roots = vec![serde_json::Value::Null; 16];
            roots[0] = serde_json::json!(super::super::CURRENT_GRAPH17_FORMAT);
            let records = vec![serde_json::json!(["string", 0, 1, 1]); count];
            let aliases = vec![serde_json::Value::Null; count];
            let input = serde_json::to_vec(&serde_json::json!([
                super::super::CURRENT_PROTOCOL17_FORMAT,
                roots,
                records,
                aliases,
            ]))
            .unwrap();
            let limits = NativeCurrentGraph17ReadLimits {
                maximum_requested: 1_048_576,
                maximum_target_requested: 1_048_576,
                maximum_nodes: 4096,
                maximum_depth: 64,
            };
            let projected = native_current_graph17_banks_data(&input, limits).unwrap();
            let mut destination = None;

            // The inert component nulls cannot pass the semantic reader. Its
            // retained raw and three alias-bank allocations remain measurable.
            assert!(
                read_native_current_graph17_with_limits_into_data(&input, &mut destination, limits)
                    .is_err()
            );
            let actual = destination.as_ref().unwrap();
            assert!(actual.completed_data().is_none());
            assert_eq!(
                actual
                    .retained_requested_storage_data(limits.maximum_requested)
                    .unwrap(),
                projected
            );
        }
    }

    #[test]
    fn parser_axis_failure_keeps_actual_raw_once_owner() {
        let input = br#"["source-private.cnp-protocol/17",[]]"#;
        let mut destination = None;
        let limits = NativeCurrentGraph17ReadLimits {
            maximum_requested: 4096,
            maximum_target_requested: 4096,
            maximum_nodes: 1,
            maximum_depth: 64,
        };

        assert!(
            read_native_current_graph17_with_limits_into_data(input, &mut destination, limits,)
                .is_err()
        );

        let retained = destination.as_ref().expect("partial owner retained");
        assert_eq!(retained.raw, input);
        assert!(retained.completed_data().is_none());
        assert_eq!(
            retained.retained_requested_storage_data(4096).unwrap(),
            input.len()
        );
        assert!(
            read_native_current_graph17_with_limits_into_data(b"null", &mut destination, limits,)
                .is_err()
        );
        assert_eq!(destination.as_ref().unwrap().raw, input);
    }

    #[test]
    fn insufficient_raw_credit_installs_owner_before_refusal() {
        let input = b"[false]";
        let mut destination = None;

        assert!(read_native_current_graph17_into_data(input, &mut destination, 1).is_err());

        let retained = destination
            .as_ref()
            .expect("owner installed before refusal");
        assert!(retained.raw.is_empty());
        assert_eq!(retained.raw.capacity(), 0);
        assert_eq!(retained.retained_requested_storage_data(1).unwrap(), 0);
        assert!(retained.validate_data().is_err());
    }
}
