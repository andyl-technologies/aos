//! Durable Mount source acquisition storage and recovery.
//!
//! Namespace 40 is hard-cut to five exact `AOSMSA02` record kinds. Recovery
//! materializes acquisition, holder-sequence, provider-head, provider-session,
//! and provider-query-attempt maps, then validates their complete object graph.
//! No `AOSMSA01` value, v1 key, migration alias, or partial graph is accepted.
//!
//! ```text
//! acquisition = "aos.mount.source-acquisition.v2\0" || acquisition-id[32]
//! head        = "aos.mount.source-provider-head.v2\0" || holder[16] || provider[16]
//! holder-seq  = "aos.mount.source-holder-sequence.v2\0" || holder[16]
//! session     = "aos.mount.source-provider-session.v2\0" || session-id[32]
//! attempt     = "aos.mount.source-provider-query-attempt.v2\0" || attempt-id[32]
//! ```
//!
//! Shared typed records are nonauthorizing data. This table keeps its maps and
//! transitions private; mutations consume purpose-specific provider-security
//! capabilities and protected journal authority. Public Mount recovery exposes
//! only read-only views and the existing Mount 2.0 wire projection. No listener,
//! service dispatch, or feature advertisement can construct those transitions,
//! so production dispatch remains inert.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceResponse, InventoryMountSourceAcquisitionsResponse,
    ReleaseMountSourceAcquisitionResponse,
};
use aos_sandbox::journal::{Journal, RecordNamespace};
use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountSourceAcquisitionStateV2, validate_mount_source_state_graph_v2,
};
use buffa::Message as _;

use crate::Result;

mod checkpoint;
mod format;
mod history;
mod inventory;
mod lifecycle;
mod model;
mod outcome;
mod projection;
mod release;
mod release_authority;
mod replacement;
mod reservation;
mod retry;
mod security;
mod transition;
mod validation;
mod wire;

pub(crate) use lifecycle::{CommittedSourceConsumptionV2, SourceConsumptionCommitV2};
pub(crate) use outcome::{ConsumedProviderOutcomeV2, RecoveredProviderOutcomeConsumptionV2};
pub(crate) use release::ReservedReleaseProviderQueryV2;
pub(crate) use reservation::{ReservedProviderQueryV2, SentProviderQueryV2};

use format::{
    MAXIMUM_SOURCE_ACQUISITIONS, MAXIMUM_SOURCE_HOLDER_SEQUENCES, MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
    MAXIMUM_SOURCE_PROVIDER_HEADS, MAXIMUM_SOURCE_PROVIDER_SESSIONS, state_error,
};
use model::{
    HolderSequenceV2, ProviderAttemptStateV2, ProviderMethodV2, SourceAcquisitionRowV2,
    SourceProviderHeadV2, SourceProviderQueryAttemptV2, SourceProviderSessionV2,
};
pub use model::{SourceAcquisitionPhaseV2, SourceAcquisitionProofClassV2};
use wire::source_acquisition_record;

/// Maximum retained acquisition rows in one Mount journal.
pub const MAXIMUM_SOURCE_ACQUISITION_ROWS: usize = MAXIMUM_SOURCE_ACQUISITIONS;
/// Maximum stable holder/provider heads in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_HEAD_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_HEADS;
/// Maximum stable holder-wide sequence floors in one Mount journal.
pub const MAXIMUM_SOURCE_HOLDER_SEQUENCE_ROWS: usize = MAXIMUM_SOURCE_HOLDER_SEQUENCES;
/// Maximum immutable authenticated provider sessions in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_SESSION_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_SESSIONS;
/// Maximum immutable provider query attempts in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_ATTEMPT_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_ATTEMPTS;

/// Materializes the complete validated `AOSMSA02` object graph.
#[derive(Clone, Debug)]
pub struct SourceAcquisitionTableV2 {
    acquisitions: BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    holder_sequences: BTreeMap<[u8; 16], HolderSequenceV2>,
    provider_heads: BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV2>,
    provider_sessions: BTreeMap<[u8; 32], SourceProviderSessionV2>,
    provider_attempts: BTreeMap<[u8; 32], SourceProviderQueryAttemptV2>,
}

/// Owns fixed Mount source state and its sole protected journal root.
///
/// This dormant integration wraps the existing Mount-manager startup owner;
/// it does not open a second trust root. Consumption access is lent only with
/// the purpose-limited opaque journal authority and cannot outlive this owner.
pub struct FixedMountSourceAcquisitionOwnerV2 {
    protected: aos_sandbox::MountManagerStartupProtectedOwnerV1,
    table: SourceAcquisitionTableV2,
}

impl core::fmt::Debug for FixedMountSourceAcquisitionOwnerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedMountSourceAcquisitionOwnerV2([protected owner])")
    }
}

impl FixedMountSourceAcquisitionOwnerV2 {
    /// Opens the existing fixed Mount journal owner and fully replays AOSMSA02.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed root, lock, startup policy, consumption
    /// scope, or complete canonical source-acquisition graph is invalid.
    #[doc(hidden)]
    pub fn open_fixed() -> Result<(Self, aos_sandbox::MountManagerStartupProtectedOpenReportV1)> {
        let (mut protected, report) =
            aos_sandbox::MountManagerStartupProtectedOwnerV1::open_fixed_protected()
                .map_err(|error| crate::MountError::State(error.to_string()))?;
        let table = {
            let authority = protected
                .source_consumption_authority()
                .map_err(|error| crate::MountError::State(error.to_string()))?;
            SourceAcquisitionTableV2::recover_from_consumption_authority(&authority)?
        };
        Ok((Self { protected, table }, report))
    }

    /// Runs one operation under the existing fixed consumption authority.
    ///
    /// The closure receives only the validated table and purpose-specific
    /// journal handoff. It cannot retain either borrow or obtain the raw
    /// journal, startup authority, or another protected namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed owner cannot re-establish its protected
    /// consumption scope or when `operation` rejects current state.
    #[doc(hidden)]
    pub fn with_consumption_authority<R>(
        &mut self,
        operation: impl for<'authority> FnOnce(
            &mut SourceAcquisitionTableV2,
            &mut aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'authority>,
        ) -> Result<R>,
    ) -> Result<R> {
        let mut authority = self
            .protected
            .source_consumption_authority()
            .map_err(|error| crate::MountError::State(error.to_string()))?;
        operation(&mut self.table, &mut authority)
    }

    /// Runs one operation under the exact fixed namespace-40 owner claim.
    ///
    /// The purpose wrapper may lend the raw claim only through its
    /// higher-ranked nonescaping borrow. This permits nesting a fixed
    /// Root-Mount session operation without making caller-selected journal
    /// authority usable by any public SourceProvider transition.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed owner cannot establish its exact
    /// namespace-40 scope or when `operation` rejects current state.
    #[doc(hidden)]
    pub fn with_source_acquisition_authority<R>(
        &mut self,
        operation: impl for<'authority> FnOnce(
            &mut SourceAcquisitionTableV2,
            &mut aos_sandbox::MountSourceAcquisitionJournalAuthorityV2<'authority>,
        ) -> Result<R>,
    ) -> Result<R> {
        let mut authority = self
            .protected
            .source_acquisition_authority()
            .map_err(|error| crate::MountError::State(error.to_string()))?;
        operation(&mut self.table, &mut authority)
    }
}

impl SourceAcquisitionTableV2 {
    /// Reconstructs the complete canonical `AOSMSA02` namespace-40 graph.
    ///
    /// # Errors
    ///
    /// Returns an error for a v1 or otherwise unsupported envelope, unknown or
    /// noncanonical JSON, a key or record-digest mismatch, a count/value limit,
    /// or any invalid, aliased, dangling, cyclic, or contradictory graph edge.
    pub fn recover(journal: &Journal) -> Result<Self> {
        let state = validate_mount_source_state_graph_v2(
            journal.records(RecordNamespace::MountSourceAcquisition),
        )?;
        Ok(Self {
            acquisitions: state.acquisitions,
            holder_sequences: state.holder_sequences,
            provider_heads: state.provider_heads,
            provider_sessions: state.provider_sessions,
            provider_attempts: state.provider_attempts,
        })
    }

    /// Reconstructs state through the fixed-owner source-consumption authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the complete current namespace-40 graph is
    /// canonical, bounded, and valid under the retained fixed journal lock.
    #[doc(hidden)]
    pub fn recover_from_consumption_authority(
        authority: &aos_sandbox::MountSourceConsumptionJournalAuthorityV1<'_>,
    ) -> Result<Self> {
        let state = validate_mount_source_state_graph_v2(authority.records()?)?;
        Ok(Self {
            acquisitions: state.acquisitions,
            holder_sequences: state.holder_sequences,
            provider_heads: state.provider_heads,
            provider_sessions: state.provider_sessions,
            provider_attempts: state.provider_attempts,
        })
    }

    pub(super) fn state(&self) -> MountSourceAcquisitionStateV2 {
        MountSourceAcquisitionStateV2 {
            acquisitions: self.acquisitions.clone(),
            holder_sequences: self.holder_sequences.clone(),
            provider_heads: self.provider_heads.clone(),
            provider_sessions: self.provider_sessions.clone(),
            provider_attempts: self.provider_attempts.clone(),
        }
    }

    /// Returns acquisition views in canonical acquisition-ID order.
    pub fn acquisitions(&self) -> impl Iterator<Item = SourceAcquisitionViewV2<'_>> {
        self.acquisitions
            .values()
            .map(|row| SourceAcquisitionViewV2 { row })
    }

    /// Returns one recovered acquisition view.
    #[must_use]
    pub fn acquisition(&self, acquisition_id: &[u8; 32]) -> Option<SourceAcquisitionViewV2<'_>> {
        self.acquisitions
            .get(acquisition_id)
            .map(|row| SourceAcquisitionViewV2 { row })
    }

    /// Returns provider-head views in stable holder/provider order.
    pub fn provider_heads(&self) -> impl Iterator<Item = SourceProviderHeadViewV2<'_>> {
        self.provider_heads
            .values()
            .map(|head| SourceProviderHeadViewV2 { head })
    }

    /// Returns holder-wide acquisition sequence floors in stable-holder order.
    pub fn holder_sequences(&self) -> impl Iterator<Item = HolderSequenceViewV2<'_>> {
        self.holder_sequences
            .values()
            .map(|sequence| HolderSequenceViewV2 { sequence })
    }

    /// Returns immutable provider-session views in session-ID order.
    pub fn provider_sessions(&self) -> impl Iterator<Item = SourceProviderSessionViewV2<'_>> {
        self.provider_sessions
            .values()
            .map(|session| SourceProviderSessionViewV2 { session })
    }

    /// Returns immutable provider-attempt views in attempt-ID order.
    pub fn provider_attempts(&self) -> impl Iterator<Item = SourceProviderQueryAttemptViewV2<'_>> {
        self.provider_attempts
            .values()
            .map(|attempt| SourceProviderQueryAttemptViewV2 { attempt })
    }

    /// Encodes one canonical bounded source-acquisition inventory response.
    ///
    /// The response is a broker-returned observation, not independent proof of
    /// the syscall writer. Broker-session authentication and deployment
    /// confinement remain required before a controller treats it as current.
    ///
    /// # Errors
    ///
    /// Returns an error for sentinel snapshot identities, a zero journal
    /// sequence, a failed private-to-wire projection, or a response over the
    /// global protocol maximum.
    pub fn encode_inventory_response(
        &self,
        kernel_boot_id: [u8; 16],
        journal_sequence: u64,
        broker_instance_id: [u8; 16],
    ) -> Result<Vec<u8>> {
        if kernel_boot_id == [0; 16] || journal_sequence == 0 || broker_instance_id == [0; 16] {
            return Err(state_error(
                "source acquisition inventory header is invalid",
            ));
        }
        let acquisitions = self
            .acquisitions
            .values()
            .map(|row| source_acquisition_record(self, row))
            .collect::<Result<Vec<_>>>()?;
        let bytes = InventoryMountSourceAcquisitionsResponse {
            kernel_boot_id: kernel_boot_id.to_vec(),
            journal_sequence,
            acquisitions,
            broker_instance_id: broker_instance_id.to_vec(),
            ..Default::default()
        }
        .encode_to_vec();
        if bytes.len() > aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES as usize {
            return Err(state_error(
                "source acquisition inventory exceeds the global protocol maximum",
            ));
        }
        Ok(bytes)
    }

    /// Encodes one canonical Acquire response selected by acquisition ID.
    ///
    /// The row, terminal attempt, and immutable session are joined through
    /// exact private record references owned by this recovered table.
    ///
    /// # Errors
    ///
    /// Returns an error when the acquisition is absent or its private evidence
    /// graph cannot be projected to the unchanged Mount 2.0 response.
    pub fn encode_acquire_response(&self, acquisition_id: [u8; 32]) -> Result<Vec<u8>> {
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition response row is missing"))?;
        let bytes = AcquireMountSourceResponse {
            record: Some(source_acquisition_record(self, row)?).into(),
            ..Default::default()
        }
        .encode_to_vec();
        if bytes.len() > aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES as usize {
            return Err(state_error(
                "source acquisition response exceeds the global protocol maximum",
            ));
        }
        Ok(bytes)
    }

    /// Encodes one canonical Release response selected by acquisition ID.
    ///
    /// The row, terminal attempt, and immutable session are joined through
    /// exact private record references owned by this recovered table.
    ///
    /// # Errors
    ///
    /// Returns an error when the acquisition is absent or its private evidence
    /// graph cannot be projected to the unchanged Mount 2.0 response.
    pub fn encode_release_response(&self, acquisition_id: [u8; 32]) -> Result<Vec<u8>> {
        let row = self
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| state_error("source acquisition response row is missing"))?;
        let bytes = ReleaseMountSourceAcquisitionResponse {
            record: Some(source_acquisition_record(self, row)?).into(),
            ..Default::default()
        }
        .encode_to_vec();
        if bytes.len() > aos_sandbox_protocol::MAXIMUM_RESPONSE_BYTES as usize {
            return Err(state_error(
                "source acquisition response exceeds the global protocol maximum",
            ));
        }
        Ok(bytes)
    }
}

/// Is a read-only view of one stable holder's non-reuse sequence floor.
#[derive(Clone, Copy, Debug)]
pub struct HolderSequenceViewV2<'a> {
    sequence: &'a HolderSequenceV2,
}

impl HolderSequenceViewV2<'_> {
    /// Returns the stable holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(self) -> [u8; 16] {
        self.sequence.holder_authority_id
    }

    /// Returns the only sequence eligible for a fresh provider acquisition.
    #[must_use]
    pub const fn next_acquisition_sequence(self) -> u64 {
        self.sequence.next_acquisition_sequence
    }

    /// Returns the greatest sequence that can never be allocated again.
    #[must_use]
    pub const fn non_reuse_floor(self) -> u64 {
        self.sequence.last_allocated_acquisition_sequence
    }
}

/// Is a read-only view of one recovered acquisition row.
#[derive(Clone, Copy, Debug)]
pub struct SourceAcquisitionViewV2<'a> {
    row: &'a SourceAcquisitionRowV2,
}

impl SourceAcquisitionViewV2<'_> {
    /// Returns the Mount-minted stable acquisition ID.
    #[must_use]
    pub const fn acquisition_id(self) -> [u8; 32] {
        self.row.acquisition_id
    }

    /// Returns the holder-authority-scoped SourceProvider acquisition ID.
    #[must_use]
    pub const fn provider_acquisition_id(self) -> [u8; 32] {
        self.row.provider_acquisition.acquisition_id
    }

    /// Returns the monotone sequence committed into the SourceProvider ID.
    #[must_use]
    pub const fn provider_acquisition_sequence(self) -> u64 {
        self.row.provider_acquisition.acquisition_sequence
    }

    /// Returns the holder authority tuple that scopes the provider identity.
    #[must_use]
    pub const fn provider_acquisition_holder(self) -> ([u8; 16], u64, [u8; 32]) {
        (
            self.row.provider_acquisition.holder_authority_id,
            self.row.provider_acquisition.holder_authority_generation,
            self.row.provider_acquisition.holder_authority_digest,
        )
    }

    /// Returns the monotonic row revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.row.revision
    }

    /// Returns the exact lifecycle phase.
    #[must_use]
    pub const fn phase(self) -> SourceAcquisitionPhaseV2 {
        self.row.phase
    }

    /// Returns the corruption-protected canonical record digest.
    #[must_use]
    pub const fn record_digest(self) -> [u8; 32] {
        self.row.record_digest
    }
}

/// Is a read-only view of one stable provider head.
#[derive(Clone, Copy, Debug)]
pub struct SourceProviderHeadViewV2<'a> {
    head: &'a SourceProviderHeadV2,
}

impl SourceProviderHeadViewV2<'_> {
    /// Returns the stable holder authority ID.
    #[must_use]
    pub const fn holder_authority_id(self) -> [u8; 16] {
        self.head.scope.holder_authority_id
    }

    /// Returns the stable provider authority ID.
    #[must_use]
    pub const fn provider_authority_id(self) -> [u8; 16] {
        self.head.scope.provider_authority_id
    }

    /// Returns the current immutable session ID.
    #[must_use]
    pub const fn current_session_id(self) -> [u8; 32] {
        self.head.current_session_id
    }

    /// Returns the current projection epoch and digest.
    #[must_use]
    pub const fn projection(self) -> (u64, [u8; 32]) {
        (
            self.head.current_projection_epoch,
            self.head.current_projection_digest,
        )
    }

    /// Reports whether crash recovery blocks normal provider work.
    #[must_use]
    pub const fn recovery_required(self) -> bool {
        self.head.recovery_barrier.is_some()
    }
}

/// Is a read-only view of one immutable authenticated session record.
#[derive(Clone, Copy, Debug)]
pub struct SourceProviderSessionViewV2<'a> {
    session: &'a SourceProviderSessionV2,
}

impl SourceProviderSessionViewV2<'_> {
    /// Returns the content-derived session ID.
    #[must_use]
    pub const fn session_id(self) -> [u8; 32] {
        self.session.session_id
    }

    /// Returns the kernel boot observed for the provider execution.
    #[must_use]
    pub const fn kernel_boot_id(self) -> [u8; 16] {
        self.session.kernel_boot_id
    }

    /// Returns the ordered four-signer commitment.
    #[must_use]
    pub const fn signer_set_commitment(self) -> [u8; 32] {
        self.session.signer_set_commitment
    }
}

/// Is a read-only view of one immutable provider query attempt.
#[derive(Clone, Copy, Debug)]
pub struct SourceProviderQueryAttemptViewV2<'a> {
    attempt: &'a SourceProviderQueryAttemptV2,
}

impl SourceProviderQueryAttemptViewV2<'_> {
    /// Returns the content-derived attempt ID.
    #[must_use]
    pub const fn attempt_id(self) -> [u8; 32] {
        self.attempt.attempt_id
    }

    /// Returns the exact request sequence reserved by this attempt.
    #[must_use]
    pub const fn request_sequence(self) -> u64 {
        self.attempt.request_sequence
    }

    /// Returns the SourceProvider acquisition ID for Acquire or Release.
    #[must_use]
    pub const fn provider_acquisition_id(self) -> Option<[u8; 32]> {
        match self.attempt.provider_acquisition {
            Some(value) => Some(value.acquisition_id),
            None => None,
        }
    }

    /// Returns the holder-scoped acquisition sequence for Acquire or Release.
    #[must_use]
    pub const fn provider_acquisition_sequence(self) -> Option<u64> {
        match self.attempt.provider_acquisition {
            Some(value) => Some(value.acquisition_sequence),
            None => None,
        }
    }

    /// Returns whether the attempt remains reserved and unresolved.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(&self.attempt.state, ProviderAttemptStateV2::Reserved)
    }

    /// Returns the closed SourceProvider method name.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self.attempt.method {
            ProviderMethodV2::Acquire => "acquire",
            ProviderMethodV2::Release => "release",
            ProviderMethodV2::Inventory => "inventory",
        }
    }
}
