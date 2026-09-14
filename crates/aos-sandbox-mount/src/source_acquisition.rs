//! Durable Mount source acquisition storage and recovery.
//!
//! Namespace 40 is hard-cut to four exact `AOSMSA02` record kinds. Recovery
//! materializes immutable acquisition, provider-head, provider-session, and
//! provider-query-attempt maps, then validates their complete object graph.
//! No `AOSMSA01` value, v1 key, migration alias, or partial graph is accepted.
//!
//! ```text
//! acquisition = "aos.mount.source-acquisition.v2\0" || acquisition-id[32]
//! head        = "aos.mount.source-provider-head.v2\0" || holder[16] || provider[16]
//! session     = "aos.mount.source-provider-session.v2\0" || session-id[32]
//! attempt     = "aos.mount.source-provider-query-attempt.v2\0" || attempt-id[32]
//! ```
//!
//! This partition deliberately contains no mutation API. Durable records are
//! private, and the recovered table exposes only read-only views and the
//! existing Mount 2.0 wire projection. Provider session/currentness brands,
//! death evidence, and atomic transition authority arrive in a later sealed
//! partition; consequently production dispatch remains inert.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceResponse, InventoryMountSourceAcquisitionsResponse,
    ReleaseMountSourceAcquisitionResponse,
};
use aos_sandbox::journal::{Journal, RecordNamespace};
use buffa::Message as _;

use crate::Result;

mod checkpoint;
mod format;
mod history;
mod model;
mod projection;
mod validation;
mod wire;

use format::{
    decode_value, key_kind, state_error, RecordKindV2, MAXIMUM_SOURCE_ACQUISITIONS,
    MAXIMUM_SOURCE_PROVIDER_ATTEMPTS, MAXIMUM_SOURCE_PROVIDER_HEADS,
    MAXIMUM_SOURCE_PROVIDER_SESSIONS,
};
use model::{
    ProviderAttemptStateV2, ProviderMethodV2, SourceAcquisitionRowV2, SourceProviderHeadV2,
    SourceProviderQueryAttemptV2, SourceProviderSessionV2, StoredRecordV2,
};
pub use model::{SourceAcquisitionPhaseV2, SourceAcquisitionProofClassV2};
use validation::validate_recovered_table;
use wire::source_acquisition_record;

/// Maximum retained acquisition rows in one Mount journal.
pub const MAXIMUM_SOURCE_ACQUISITION_ROWS: usize = MAXIMUM_SOURCE_ACQUISITIONS;
/// Maximum stable holder/provider heads in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_HEAD_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_HEADS;
/// Maximum immutable authenticated provider sessions in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_SESSION_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_SESSIONS;
/// Maximum immutable provider query attempts in one Mount journal.
pub const MAXIMUM_SOURCE_PROVIDER_ATTEMPT_ROWS: usize = MAXIMUM_SOURCE_PROVIDER_ATTEMPTS;

/// Materializes the complete validated `AOSMSA02` object graph.
#[derive(Debug)]
pub struct SourceAcquisitionTableV2 {
    acquisitions: BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
    provider_heads: BTreeMap<([u8; 16], [u8; 16]), SourceProviderHeadV2>,
    provider_sessions: BTreeMap<[u8; 32], SourceProviderSessionV2>,
    provider_attempts: BTreeMap<[u8; 32], SourceProviderQueryAttemptV2>,
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
        let mut acquisitions = BTreeMap::new();
        let mut provider_heads = BTreeMap::new();
        let mut provider_sessions = BTreeMap::new();
        let mut provider_attempts = BTreeMap::new();
        let mut acquisition_count = 0usize;
        let mut provider_head_count = 0usize;
        let mut provider_session_count = 0usize;
        let mut provider_attempt_count = 0usize;

        for (key, value) in journal.records(RecordNamespace::MountSourceAcquisition) {
            let (count, maximum) = match key_kind(key)? {
                RecordKindV2::Acquisition => (&mut acquisition_count, MAXIMUM_SOURCE_ACQUISITIONS),
                RecordKindV2::ProviderHead => {
                    (&mut provider_head_count, MAXIMUM_SOURCE_PROVIDER_HEADS)
                }
                RecordKindV2::ProviderSession => (
                    &mut provider_session_count,
                    MAXIMUM_SOURCE_PROVIDER_SESSIONS,
                ),
                RecordKindV2::ProviderQueryAttempt => (
                    &mut provider_attempt_count,
                    MAXIMUM_SOURCE_PROVIDER_ATTEMPTS,
                ),
            };
            *count = count
                .checked_add(1)
                .ok_or_else(|| state_error("AOSMSA02 materialization count overflow"))?;
            if *count > maximum {
                return Err(state_error("AOSMSA02 record kind exceeds its fixed bound"));
            }
            match decode_value(key, value)? {
                StoredRecordV2::Acquisition { value } => {
                    if acquisitions.insert(value.acquisition_id, value).is_some() {
                        return Err(state_error("duplicate AOSMSA02 acquisition identity"));
                    }
                }
                StoredRecordV2::ProviderHead { value } => {
                    let identity = (
                        value.scope.holder_authority_id,
                        value.scope.provider_authority_id,
                    );
                    if provider_heads.insert(identity, value).is_some() {
                        return Err(state_error("duplicate AOSMSA02 provider-head identity"));
                    }
                }
                StoredRecordV2::ProviderSession { value } => {
                    if provider_sessions.insert(value.session_id, value).is_some() {
                        return Err(state_error("duplicate AOSMSA02 provider-session identity"));
                    }
                }
                StoredRecordV2::ProviderQueryAttempt { value } => {
                    if provider_attempts.insert(value.attempt_id, value).is_some() {
                        return Err(state_error("duplicate AOSMSA02 provider-attempt identity"));
                    }
                }
            }
        }

        let table = Self {
            acquisitions,
            provider_heads,
            provider_sessions,
            provider_attempts,
        };
        validate_recovered_table(&table)?;
        Ok(table)
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

    /// Returns whether the attempt remains reserved and unresolved.
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(self.attempt.state, ProviderAttemptStateV2::Reserved)
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
