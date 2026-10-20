//! Authenticates the complete native Host Session roster and immutable frames.
//!
//! The enclosing Root owner pays from its actual captured prefix before this
//! decoder grows any entry. Each row keeps its real checkpoint, full signed
//! traffic and selected historical request/outcome originals. Ordinary and
//! fresh cleanup heads remain distinct. An authenticated pending request stays
//! pending; neither a signed error nor one terminal archive proves absence.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::BrokerSessionDurablePhaseV1;
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_broker_session_protocol::profile;
use aos_sandbox_protocol::authenticated_session::{
    all_methods::{AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1},
    historical_method::{historical_client_request, historical_terminal_observation_v2},
    history_archive::*,
    stored_history::{StoredBrokerSessionPurposeDataV2, classify_protocol_key_v2},
};

use crate::policy_compiler::create_storage_current::controller_readonly::storage_inventory::verify_execution_host_history_retaining_v2;

use super::*;

#[derive(Clone, Copy)]
enum Kind {
    Head(StoredBrokerSessionPurposeDataV2),
    Original([u8; 16]),
    Terminal([u8; 16]),
}

struct Entry {
    kind: Option<Kind>,
    stored: StoredBrokerSessionHistoryDecodeCaptureV1,
    checkpoint: HistoricalSessionCheckpointVerifyCaptureV1,
    traffic: HistoricalTrafficReplayCaptureV1,
    verified: Option<Result<SessionValues, Cause>>,
    request: Option<Result<AuthenticatedBrokerMethodRequestV1, Cause>>,
    outcome: Option<Result<AuthenticatedBrokerMethodOutcomeV1, Cause>>,
    inventory: aos_sandbox_protocol::authenticated_session::historical_method::HistoricalDeleteCleanupMethodCaptureV4,
    stop_child: aos_sandbox_protocol::authenticated_session::historical_method::HistoricalStartResourceMethodCaptureV2,
    body: Option<Result<(), Cause>>,
}

impl Entry {
    fn new() -> Self {
        Self {
            kind: None,
            stored: Default::default(),
            checkpoint: Default::default(),
            traffic: Default::default(),
            verified: None,
            request: None,
            outcome: None,
            inventory: Default::default(),
            stop_child: Default::default(),
            body: None,
        }
    }

    fn observe(
        &mut self,
        kind: Kind,
        key: &[u8],
        encoded: &[u8],
        manifest: &BrokerSessionManifestV1,
        controller: (u32, u32),
    ) -> Result<(), Cause> {
        self.kind = Some(kind);
        let ordinary = canonical_protocol_key_v1(BrokerSessionProtocolV1::Host);
        let (stored_key, bytes) = match kind {
            Kind::Head(_) => (key, encoded),
            Kind::Original(id) => (
                ordinary.as_slice(),
                open_history_archive_frame_data_v1(
                    id,
                    encoded,
                    HOST_ARGUMENT_ARCHIVE_MAGIC_V1,
                    HOST_ARGUMENT_ARCHIVE_DOMAIN_V1,
                )?,
            ),
            Kind::Terminal(id) => (
                ordinary.as_slice(),
                open_history_archive_frame_data_v1(
                    id,
                    encoded,
                    HOST_TERMINAL_ARCHIVE_MAGIC_V1,
                    HOST_TERMINAL_ARCHIVE_DOMAIN_V1,
                )?,
            ),
        };
        StoredBrokerSessionHistoryV1::decode_retaining(stored_key, bytes, &mut self.stored)?;
        let stored = self
            .stored
            .stored()
            .ok_or(JournalError::ProtectedBoundary)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if (checkpoint.peer().uid, checkpoint.peer().gid) != controller {
            return Err(JournalError::ProtectedBoundary.into());
        }
        // Historical boot coordinates authenticate old traffic only. The
        // separate selected43 verifier checks its genuine fresh native boot.
        self.verified = Some(verify_execution_host_history_retaining_v2(
            manifest,
            stored,
            manifest.node_id(),
            checkpoint.context().boot_id(),
            &mut self.checkpoint,
            &mut self.traffic,
        ));
        let (_, transcript, history, _) = self
            .verified
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let head = history.head()?;
        match kind {
            Kind::Head(purpose) => {
                let valid = match purpose {
                    StoredBrokerSessionPurposeDataV2::Ordinary => {
                        !profile::is_host_no_apply_cleanup_transcript_v1(transcript)
                            && !profile::is_host_stop_cleanup_transcript_v1(transcript)
                    }
                    StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup => {
                        profile::is_host_no_apply_cleanup_transcript_v1(transcript)
                    }
                    StoredBrokerSessionPurposeDataV2::HostStopCleanup => {
                        profile::is_host_stop_cleanup_transcript_v1(transcript)
                    }
                    StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory => false,
                };
                if !valid {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                if purpose == StoredBrokerSessionPurposeDataV2::HostStopCleanup
                    && head.phase() == BrokerSessionDurablePhaseV1::Terminal
                    && head.method() == BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                {
                    let last = history.records().len().checked_sub(1)
                        .ok_or(JournalError::ProtectedBoundary)?;
                    self.inventory.observe_host_inventory_once_v4(history.records(),
                        last, checkpoint, transcript)?;
                }
            }
            Kind::Original(id) | Kind::Terminal(id) => {
                // The established legacy37/59 rows and new closed finite rows
                // exhaust these archive families. FD-bearing unrelated methods
                // never enter the historical method reconstruction below.
                if !matches!(
                    head.method(),
                    BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT
                        | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2
                        | BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                        | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                        | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                        | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
                ) {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                let last = history
                    .records()
                    .len()
                    .checked_sub(1)
                    .ok_or(JournalError::ProtectedBoundary)?;
                match kind {
                    Kind::Original(_) => {
                        if head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared
                            || head.request_id() != id
                        {
                            return Err(JournalError::ProtectedBoundary.into());
                        }
                        self.request = Some(
                            historical_client_request(
                                history.records(),
                                last,
                                checkpoint,
                                transcript,
                            )
                            .map(|(request, _)| request)
                            .map_err(|cause| cause.into()),
                        );
                        self.request
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .ok_or(JournalError::ProtectedBoundary)?;
                    }
                    Kind::Terminal(_) => {
                        if head.phase() != BrokerSessionDurablePhaseV1::Terminal {
                            return Err(JournalError::ProtectedBoundary.into());
                        }
                        self.outcome = Some(
                            historical_terminal_observation_v2(
                                history.records(),
                                last,
                                checkpoint,
                                transcript,
                            )
                            .map_err(|cause| cause.into()),
                        );
                        let outcome = self
                            .outcome
                            .as_ref()
                            .and_then(|value| value.as_ref().ok())
                            .ok_or(JournalError::ProtectedBoundary)?;
                        let request = outcome.request();
                        let closed = request.execution_availability_data_v2().is_some()
                            || request.host_before_argument_no_apply_data_v2().is_some()
                            || request.host_held_no_apply_settlement_data_v2().is_some()
                            || request
                                .host_no_apply_current_lease_query_data_v2()
                                .is_some();
                        if closed && request.request_id() != id {
                            return Err(JournalError::ProtectedBoundary.into());
                        }
                    }
                    Kind::Head(_) => return Err(JournalError::ProtectedBoundary.into()),
                }
            }
        }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.stored
            .failure()
            .map(|cause| cause as _)
            .or_else(|| self.checkpoint.failure().map(|cause| cause as _))
            .or_else(|| self.traffic.cause())
            .or_else(|| self.inventory.failure_v4())
            .or_else(|| self.stop_child.failure_v2())
            .or_else(|| {
                self.verified
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.request
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.outcome
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.body
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
    }
}

pub(in crate::policy_compiler) struct HostHistoryOriginalV2 {
    entries: Vec<Entry>,
    body: Option<Result<(), Cause>>,
    stop_dispatch: Option<Result<usize, Cause>>,
    stop_dispatch_reentry: Option<JournalError>,
    stop_child: Option<Result<usize, Cause>>,
}

impl HostHistoryOriginalV2 {
    /// Selects the actual authenticated child from the same fresh cleanup head.
    /// The sole historical method retainer verifies its request and terminal
    /// pair; the caller still owns the native read and every independent post.
    pub(in crate::policy_compiler) fn observe_stop_cleanup_child_once_v1(
        &mut self, subject: aos_sandbox_protocol::host_stop_cleanup::HostStopCleanupSubjectDataV1,
    ) -> Result<(), JournalError> {
        if self.stop_child.is_some() || !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            self.stop_dispatch_reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.stop_child = Some((|| {
            let mut selected = None;
            for (index, entry) in self.entries.iter_mut().enumerate() {
                if !matches!(entry.kind, Some(Kind::Head(StoredBrokerSessionPurposeDataV2::HostStopCleanup))) { continue; }
                if selected.is_some() { return Err(JournalError::ProtectedBoundary.into()); }
                let (_, transcript, history, _) = entry.verified.as_ref()
                    .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
                let stored = entry.stored.stored().ok_or(JournalError::ProtectedBoundary)?;
                let checkpoint = stored.checkpoint.as_ref().ok_or(JournalError::ProtectedBoundary)?;
                let mut terminals = history.records().iter().enumerate().filter(|(_, row)|
                    row.phase() == BrokerSessionDurablePhaseV1::Terminal
                        && row.method() == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                        && row.request_id() == *subject.cleanup_request_v1());
                let (terminal, _) = terminals.next().ok_or(JournalError::ProtectedBoundary)?;
                if terminals.next().is_some() { return Err(JournalError::ProtectedBoundary.into()); }
                entry.stop_child.observe_host_once_v2(history.records(), terminal, checkpoint, transcript)?;
                let request = entry.stop_child.host_apply_request_v2().ok_or(JournalError::ProtectedBoundary)?;
                if request.host_stop_cleanup_v1() != Some(&subject) {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                selected = Some(index);
            }
            selected.ok_or_else(|| JournalError::ProtectedBoundary.into())
        })());
        self.stop_cleanup_child_v1().map(|_| ())
    }

    pub(in crate::policy_compiler) fn stop_cleanup_child_v1(&self)
        -> Result<&AuthenticatedBrokerMethodOutcomeV1, JournalError> {
        if self.failure().is_some() { return Err(JournalError::ProtectedBoundary); }
        let index = *self.stop_child.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.entries.get(index).and_then(|entry| entry.stop_child.outcome_v2())
            .ok_or(JournalError::ProtectedBoundary)
    }
    /// Replays the actual original prepared Stop packet through this roster.
    ///
    /// Source A7 selects comparison bytes only. The existing authenticated
    /// method engine independently verifies the same ordinary Session's real
    /// request and its exact prepared position. Expired old coordinates remain
    /// historical DATA; this method creates no old Session or effect owner.
    pub(in crate::policy_compiler) fn observe_stop_dispatch_once_v1(
        &mut self,
        dispatch: &aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1,
    ) -> Result<(), JournalError> {
        if self.stop_dispatch.is_some() {
            self.stop_dispatch_reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.stop_dispatch = Some((|| {
            let (id, session, digest) = dispatch.sdk_request_data_v1();
            let mut selected = None;
            for (index, entry) in self.entries.iter_mut().enumerate() {
                if !matches!(entry.kind,
                    Some(Kind::Head(StoredBrokerSessionPurposeDataV2::Ordinary)))
                {
                    continue;
                }
                let (_, transcript, history, _) = entry.verified.as_ref()
                    .and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
                if transcript.session_binding() != session { continue; }
                let mut positions = history.records().iter().enumerate().filter(|(_, record)|
                    record.phase() == BrokerSessionDurablePhaseV1::RequestPrepared
                        && record.request_id() == id);
                let Some((position, _)) = positions.next() else { continue; };
                if positions.next().is_some() || selected.replace(index).is_some() {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                let checkpoint = entry.stored.stored().and_then(|stored| stored.checkpoint.as_ref())
                    .ok_or(JournalError::ProtectedBoundary)?;
                entry.request = Some(historical_client_request(history.records(), position,
                    checkpoint, transcript).map(|(request, _)| request).map_err(|cause| cause.into()));
                let request = entry.request.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                if request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
                    || request.request_id() != id || request.session_binding() != session
                    || request.signed_request_digest() != digest
                    || request.canonical_packet() != dispatch.canonical_packet()
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
            }
            selected.ok_or_else(|| JournalError::ProtectedBoundary.into())
        })());
        self.stop_dispatch_request_v1().map(|_| ())
    }

    /// Borrows only the same independently verified historical Stop request.
    pub(in crate::policy_compiler) fn stop_dispatch_request_v1(&self)
        -> Result<&AuthenticatedBrokerMethodRequestV1, JournalError> {
        if self.failure().is_some() { return Err(JournalError::ProtectedBoundary); }
        let index = self.stop_dispatch.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.entries.get(index).and_then(|entry| entry.request.as_ref())
            .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
    }

    /// Borrows the actual current Stop-cleanup Inventory3 from the full roster.
    ///
    /// The checkpoint/profile, complete traffic and canonical method decoder
    /// stay in this owner. Fresh boot, nonce, native cut, Source, current cap
    /// and target association remain the enclosing Stop issuer's obligations.
    pub(in crate::policy_compiler) fn stop_cleanup_inventory_v1(&self) -> Result<(
        &AuthenticatedBrokerMethodOutcomeV1,
        &aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse,
        [u8; 16],
    ), JournalError> {
        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut selected = self.entries.iter().filter(|entry| matches!(entry.kind,
            Some(Kind::Head(StoredBrokerSessionPurposeDataV2::HostStopCleanup))));
        let entry = selected.next().ok_or(JournalError::ProtectedBoundary)?;
        if selected.next().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (context, _, _, _) = entry.verified.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        Ok((entry.inventory.outcome_v4().ok_or(JournalError::ProtectedBoundary)?,
            entry.inventory.host_inventory_v4().ok_or(JournalError::ProtectedBoundary)?,
            context.boot_id()))
    }

    /// Borrows terminal comparison DATA from this same retained full replay.
    pub(in crate::policy_compiler::execution_no_apply_root) fn terminal_outcomes_v2(&self)
        -> impl Iterator<Item = &AuthenticatedBrokerMethodOutcomeV1> {
        self.entries.iter().filter_map(|entry|
            entry.outcome.as_ref().and_then(|value| value.as_ref().ok()))
    }

    /// Joins cleanup selection to the same fully authenticated native archive.
    /// No caller-supplied packet or reconstructed old Session supplies history.
    pub(in crate::policy_compiler::execution_no_apply_root) fn require_recovery_lineage_v2(
        &self,
        selection: &super::super::acquisition::RootNoApplyAcquisitionSelectionDataV2,
        current_boot: [u8; 16],
    ) -> Result<(bool, bool), Cause> {
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        use aos_sandbox_protocol::execution_availability::{ExecutionAvailabilityPhaseV2, decode_execution_availability_response_v2};
        use aos_sandbox_protocol::host_execution_availability::{observation::HostExecutionAvailabilityObservationV2, validate_host_execution_availability_response_v2};
        use aos_sandbox_protocol::host_execution_no_apply::{closed_host_terminal_archive_data_v2,
            held_settlement_transport::HostNoApplyHeldCommandV2};

        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let mut current_heads = 0_usize;
        let mut bound = false;
        let mut terminal = false;
        let mut sealed = false;
        let mut acknowledged = false;
        for entry in &self.entries {
            let (context, transcript, _, _) = entry.verified.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            if matches!(entry.kind, Some(Kind::Head(StoredBrokerSessionPurposeDataV2::Ordinary
                | StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup)))
                && transcript.session_binding() == selection.host_session
            {
                if context.boot_id() != current_boot {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                current_heads = current_heads.checked_add(1).ok_or(JournalError::JournalTooLarge)?;
            }
            let Some(Ok(outcome)) = &entry.outcome else { continue; };
            let request = outcome.request();
            if let Some(availability) = request.execution_availability_data_v2() {
                if availability.phase() == ExecutionAvailabilityPhaseV2::AcceptedBind
                    && availability.canonical_accepted_source() == selection.accepted_source.encode_canonical()
                {
                    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
                        else { return Err(JournalError::ProtectedBoundary.into()); };
                    validate_host_execution_availability_response_v2(exact_body, availability,
                        request.session_binding(), request.signed_request_digest())
                        ?;
                    let observed = HostExecutionAvailabilityObservationV2::decode_canonical(
                        &decode_execution_availability_response_v2(exact_body)
                            ?)
                        ?;
                    if observed != selection.historical_availability {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                    bound = true;
                }
            }
            if request.host_before_argument_no_apply_data_v2().is_some_and(|request|
                !request.is_query() && request.source() == selection.accepted_source) {
                let group = closed_host_terminal_archive_data_v2(outcome)
                    ?;
                if group.marker() == selection.marker {
                    if group.archive_head().as_bytes() != &selection.terminal_archive
                        || group.signed_terminal_outcome().as_bytes() != &selection.signed_terminal
                    {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                    terminal = true;
                }
            }
            if let Some(held) = request.host_held_no_apply_settlement_data_v2() {
                let selected = match held.command_v2() {
                    HostNoApplyHeldCommandV2::FloorSeal { comparison, .. }
                    | HostNoApplyHeldCommandV2::Acknowledge { comparison, .. } =>
                        comparison.fields().accepted_source == selection.accepted_source,
                    HostNoApplyHeldCommandV2::RecoveryPreliminary { .. }
                    | HostNoApplyHeldCommandV2::Preliminary { .. } => false,
                };
                if selected {
                    if !matches!(outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. }) {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                    match held.command_v2() {
                        HostNoApplyHeldCommandV2::FloorSeal { .. } => sealed = true,
                        HostNoApplyHeldCommandV2::Acknowledge { .. } => acknowledged = true,
                        _ => return Err(JournalError::ProtectedBoundary.into()),
                    }
                }
            }
        }
        if current_heads != 1 || !bound || !terminal {
            return Err(JournalError::ProtectedBoundary.into());
        }
        // An original selected Seal/ACK without its exact terminal archive is
        // ambiguous. A different current head or a signed error is no absence
        // proof, even when all older traffic authenticated successfully.
        for entry in &self.entries {
            let Some(Ok(request)) = &entry.request else { continue; };
            let Some(held) = request.host_held_no_apply_settlement_data_v2() else { continue; };
            let selected = match held.command_v2() {
                HostNoApplyHeldCommandV2::FloorSeal { comparison, .. }
                | HostNoApplyHeldCommandV2::Acknowledge { comparison, .. } =>
                    comparison.fields().accepted_source == selection.accepted_source,
                _ => false,
            };
            if selected && !self.entries.iter().any(|terminal| {
                terminal.outcome.as_ref().and_then(|value| value.as_ref().ok())
                    .is_some_and(|outcome| outcome.request().signed_request_digest() == request.signed_request_digest()
                        && outcome.request().session_binding() == request.session_binding())
            }) {
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        Ok((sealed, acknowledged))
    }

    pub(in crate::policy_compiler) fn new() -> Self {
        Self {
            entries: Vec::new(),
            body: None,
            stop_dispatch: None,
            stop_dispatch_reentry: None,
            stop_child: None,
        }
    }

    pub(in crate::policy_compiler) fn receiving_demand(
        prefix: usize,
        entries: usize,
    ) -> Result<ResourceVector, JournalError> {
        let request = RequestCapture::dynamic_receiving_demand_v1(prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        let outcome = OutcomeCapture::dynamic_receiving_demand_v1(prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        // The fresh cleanup head retains its complete generated Inventory3
        // beside the independently reconstructed historical outcomes. Its
        // actual width is bounded by this same captured prefix, and its model
        // uses the existing method-owned supplier rather than a raw byte guess.
        let inventory = OutcomeCapture::controller_inventory_dynamic_receiving_demand_v1(
            BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME, prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        // The actual native prefix bounds the sum of all framed stored bytes.
        // Each one-shot entry retains its full replay and selected semantic
        // captures; this prices per-entry carriers as well as raw model planes.
        let bytes = prefix
            .checked_mul(20)
            .and_then(|n| n.checked_add(entries.checked_mul(size_of::<Entry>())?.checked_mul(3)?))
            .and_then(|n| {
                n.checked_add(
                    prefix
                        .checked_mul(size_of::<BrokerSessionDurableRecordV1>())?
                        .checked_mul(6)?,
                )
            })
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(request
            .checked_add(outcome)?
            .checked_add(inventory)?
            // The selected child retains a second complete authenticated
            // request/outcome pair beside the general historical captures and
            // the fresh inventory. Inline Entry size does not price this
            // distinct dynamic decoder backing.
            .checked_add(request)?
            .checked_add(outcome)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    pub(in crate::policy_compiler) fn observe_once(
        &mut self,
        native: &RootFixedNativeReadbackV1<'_>,
        manifest: &BrokerSessionManifestV1,
        controller: (u32, u32),
    ) -> Result<(), JournalError> {
        if self.body.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.body = Some(self.observe_body(native, manifest, controller));
        if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn observe_body(
        &mut self,
        native: &RootFixedNativeReadbackV1<'_>,
        manifest: &BrokerSessionManifestV1,
        controller: (u32, u32),
    ) -> Result<(), Cause> {
        for ((namespace, key), encoded) in native.state {
            if *namespace != RecordNamespace::BrokerSessionTraffic {
                continue;
            }
            let kind = if key.len() == 9 {
                let (purpose, protocol) = classify_protocol_key_v2(key)?;
                if protocol != BrokerSessionProtocolV1::Host {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                Kind::Head(purpose)
            } else if key.len() == 24 {
                let id: [u8; 16] = key[8..]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                if key.starts_with(HOST_ORIGINAL_SESSION_KEY_MAGIC_V1) {
                    Kind::Original(id)
                } else if key.starts_with(HOST_TERMINAL_SESSION_KEY_MAGIC_V1) {
                    Kind::Terminal(id)
                } else {
                    return Err(JournalError::ProtectedBoundary.into());
                }
            } else {
                return Err(JournalError::ProtectedBoundary.into());
            };
            // The native map bounds this finite roster before Vec growth. All
            // failed descendants stay in this reached entry through Root posts.
            self.entries.push(Entry::new());
            let entry = self
                .entries
                .last_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            entry.body = Some(entry.observe(kind, key, encoded, manifest, controller));
            if !matches!(entry.body, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        Ok(())
    }

    pub(in crate::policy_compiler) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.entries.iter().find_map(Entry::failure).or_else(|| {
            self.stop_dispatch_reentry.as_ref().map(|cause| cause as _)
        }).or_else(|| {
            self.stop_dispatch.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause.as_ref())
        }).or_else(|| {
            self.stop_child.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause.as_ref())
        }).or_else(|| {
            self.body
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref())
        })
    }
}
