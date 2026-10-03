//! Sealed mutually authenticated hello typestates.

mod mount_request;
mod provider;
mod root_mount;

pub(crate) use mount_request::original_kernel_clock;

use core::cell::Cell;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use aos_sandbox_linux::seqpacket::{RecordBindingError, SeqpacketError};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;

use crate::SourceProviderSecurityError;
use crate::carrier::{
    CarrierFailureV1, InertSourceProviderCarrierV1, RetainedSourceProviderRecordV5,
    SelectedCarrierOpeningFailureV1, SelectedNegativeEndpointV1,
};
use crate::custody::{
    ProtectedProviderCustodyV1, ProtectedRootMountCustodyV1,
    SelectedSourceProviderCustodyOpeningV1,
};

pub use mount_request::{
    AuthorizedMountAcquireVerificationFloorV2, AuthorizedMountProviderOutcomeV2,
    CapturedMountProviderRecoveryOutcomeV2, CommittedReopenedMountSourceRootV2,
    CurrentMountProviderSessionPlanV2, HistoricalMountInventoryAuthorizationV2,
    HistoricalMountReleaseAuthorizationV2, MountProviderAuthorityTrustProjectionV2,
    MountProviderRequestProjectionV2, MountProviderRequestSendRecoveryV2,
    MountProviderSessionProjectionV2, MountProviderSignerProjectionV2, PendingNativeMountAcquireV3,
    OriginalNativeReceivedOutcomeV5, PreparedMountProviderRequestV2, ReceivedMountProviderOutcomePartsV2,
    OriginalInventoryPreparationV6, OriginalInventorySendV6, OriginalInventoryReceivedOutcomeV6,
    RecoveredMountProviderOutcomePartsV2, RecoveredMountProviderOutcomeV2,
    ReopenedMountSourceRootV2, ReservedMountProviderRequestV2, RetainedRootRecoveryAuthorizationV2,
    RootAcceptedNativeExportFenceV1, SentMountProviderRequestV2, VerifiedMountProviderOutcomeV2,
    VerifiedReceivedMountProviderOutcomeV2,
};
pub use provider::{
    OriginalNativeSigningErrorV5,
    AcquireReceiptFactsV1, CurrentProviderIngressSessionV1, CurrentProviderOriginalCarrierPacketV1,
    CurrentProviderSessionProjectionV1, CurrentRootPreparedCarrierV1, ProviderCompletionBuilderV1,
    ProviderIngressReopenCheckpointV1, ProviderOwnerSecurityFacadeV1,
    ProviderSessionSupersessionEvidenceV1, ProviderSourceProviderHandshakeStatusV1,
    ProviderSourceProviderOwnerV1, RevalidatedProviderReplayV1,
    SelectedProviderSourceProviderOwnerV1,
};
pub use root_mount::{
    AuthenticatedRootMountCatalogCurrentnessV1, AuthenticatedRootMountNativeRecoveryUnavailableV1,
    AuthenticatedRootMountRecoveryObservationV2, AuthenticatedRootMountRecoveryUnavailableV1,
    CurrentRootMountSourceProviderSessionV1, InventoryReadbackProgressV1,
    RootMountSourceProviderHandshakeStatusV1, RootMountSourceProviderOwnerV1,
    SelectedRootMountSourceProviderOwnerV1,
};

enum SelectedOpeningFailureV1 {
    Custody,
    Local(SourceProviderSecurityError),
    EndpointLookup,
    EndpointDuplicate,
    Socket(SeqpacketError),
}

/// Lends the actual first selected opening or handshake cause.
///
/// Each reference points into the same resident original owner. The value
/// grants no retry, transport, signing or custody authority and copies no owned
/// error. Its diagnostic representation reveals only the cause category.
pub enum SelectedSourceProviderFailureRefV1<'owner> {
    /// The existing fixed Source custody or protocol validator failed.
    Source(&'owner SourceProviderSecurityError),
    /// The original descriptor-subject endpoint could not be borrowed.
    Socket(&'owner SeqpacketError),
    /// Safe duplication of the same original endpoint failed.
    Endpoint(&'owner std::io::Error),
    /// The original typed packet could not be bound to the same endpoint.
    Binding(&'owner RecordBindingError),
    /// The same protected journal loan failed its actual currentness check.
    Journal(&'owner aos_sandbox::JournalError),
}

impl core::fmt::Debug for SelectedSourceProviderFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Source(_) => "SelectedSourceProviderFailureRefV1(Source)",
            Self::Socket(_) => "SelectedSourceProviderFailureRefV1(Socket)",
            Self::Endpoint(_) => "SelectedSourceProviderFailureRefV1(Endpoint)",
            Self::Binding(_) => "SelectedSourceProviderFailureRefV1(Binding)",
            Self::Journal(_) => "SelectedSourceProviderFailureRefV1(Journal)",
        })
    }
}

#[derive(Clone, Copy)]
enum HandshakeReceiveModeV1 {
    Legacy,
    Selected,
}

// Role-specific transcript checks share one closed zero-FD HELLO receive
// selection. Neither recipe widens the original carrier profile or parser.
fn receive_hello_record(
    carrier: &mut InertSourceProviderCarrierV1,
    slot: &mut Option<RetainedSourceProviderRecordV5>,
    mode: HandshakeReceiveModeV1,
) -> Result<(), CarrierFailureV1> {
    let maximum = aos_sandbox_source_provider_protocol::SOURCE_PROVIDER_HELLO_FRAME_BYTES;
    match mode {
        HandshakeReceiveModeV1::Legacy => carrier
            .receive_zero_descriptors(maximum)
            .map(|record| *slot = Some(RetainedSourceProviderRecordV5::Bound(record))),
        HandshakeReceiveModeV1::Selected => carrier
            .receive_zero_descriptors_retaining_v5(maximum, slot)
            .map(|_| ()),
    }
}

/// Parks the fixed selected role's returned opening prefixes under its socket.
///
/// The role-local entry points construct this before opening protected files.
/// The nested custody failure stays in its original reservoir; this owner
/// records only which original cause must be lent. Negative Drop closes the
/// carrier before any nested custody fields are released. Unreturned lower
/// opener prefixes and allocation funding remain independent limitations.
struct SelectedHandshakeOpeningV1 {
    socket: Option<DescriptorSubjectSocket>,
    endpoint: Option<Arc<SelectedNegativeEndpointV1>>,
    endpoint_lookup_failure: Option<SeqpacketError>,
    custody_opening: SelectedSourceProviderCustodyOpeningV1,
    provider_custody: Option<ProtectedProviderCustodyV1>,
    root_mount_custody: Option<ProtectedRootMountCustodyV1>,
    carrier: Option<InertSourceProviderCarrierV1>,
    first_failure: Option<SelectedOpeningFailureV1>,
    attempted: bool,
    armed: bool,
    ended: bool,
    shutdown_attempted: bool,
    shutdown_failure: Option<std::io::Error>,
    shutdown_unavailable: bool,
}

impl SelectedHandshakeOpeningV1 {
    fn provider(socket: DescriptorSubjectSocket) -> Self {
        Self::new(
            socket,
            ProtectedProviderCustodyV1::begin_fixed_selected_mount_source(),
        )
    }

    fn root_mount(socket: DescriptorSubjectSocket) -> Self {
        Self::new(
            socket,
            ProtectedRootMountCustodyV1::begin_fixed_selected_mount_source(),
        )
    }

    fn new(
        socket: DescriptorSubjectSocket,
        custody_opening: SelectedSourceProviderCustodyOpeningV1,
    ) -> Self {
        let mut opening = Self {
            socket: Some(socket),
            endpoint: None,
            endpoint_lookup_failure: None,
            custody_opening,
            provider_custody: None,
            root_mount_custody: None,
            carrier: None,
            first_failure: None,
            attempted: false,
            armed: true,
            ended: false,
            shutdown_attempted: false,
            shutdown_failure: None,
            shutdown_unavailable: false,
        };

        // The whole armed owner already holds the original socket before this
        // selected-only allocation. Allocation funding is not a drain proof.
        opening.endpoint = Some(Arc::new(SelectedNegativeEndpointV1::empty()));
        opening
    }

    fn open_once(&mut self) -> Result<(), SelectedSourceProviderFailureRefV1<'_>> {
        if self.attempted {
            if self.first_failure.is_none() {
                self.first_failure = Some(SelectedOpeningFailureV1::Local(
                    SourceProviderSecurityError::Poisoned,
                ));
            }
        } else {
            self.attempted = true;
            if let Err(error) = self.open_inner() {
                self.first_failure = Some(error);
            }
        }

        if self.first_failure.is_some() && self.failure().is_none() {
            self.first_failure = Some(SelectedOpeningFailureV1::Local(
                SourceProviderSecurityError::Poisoned,
            ));
        }
        if self.first_failure.is_some() {
            self.close();
        }
        match self.failure() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn failure(&self) -> Option<SelectedSourceProviderFailureRefV1<'_>> {
        match self.first_failure.as_ref() {
            Some(SelectedOpeningFailureV1::Custody) => self
                .custody_opening
                .failure()
                .map(SelectedSourceProviderFailureRefV1::Source),
            Some(SelectedOpeningFailureV1::Local(error)) => {
                Some(SelectedSourceProviderFailureRefV1::Source(error))
            }
            Some(SelectedOpeningFailureV1::EndpointLookup) => self
                .endpoint_lookup_failure
                .as_ref()
                .map(SelectedSourceProviderFailureRefV1::Socket),
            Some(SelectedOpeningFailureV1::EndpointDuplicate) => self
                .endpoint
                .as_ref()
                .and_then(|endpoint| endpoint.duplicate_failure())
                .map(SelectedSourceProviderFailureRefV1::Endpoint),
            Some(SelectedOpeningFailureV1::Socket(error)) => {
                Some(SelectedSourceProviderFailureRefV1::Socket(error))
            }
            None => None,
        }
    }

    fn open_inner(&mut self) -> Result<(), SelectedOpeningFailureV1> {
        // This +1 selected FD is a negative fence only. Park the actual Result
        // before the first custody/capacity/HELLO effect; a lower plain close
        // cannot prevent shutdown of this same original open-file-description.
        let socket = self.socket.as_ref().ok_or(SelectedOpeningFailureV1::Local(
            SourceProviderSecurityError::Poisoned,
        ))?;
        let original = match socket.as_fd() {
            Ok(original) => original,
            Err(error) => {
                self.endpoint_lookup_failure = Some(error);
                return Err(SelectedOpeningFailureV1::EndpointLookup);
            }
        };
        let endpoint = self.endpoint.as_ref().ok_or(SelectedOpeningFailureV1::Local(
            SourceProviderSecurityError::Poisoned,
        ))?;
        endpoint.retain_duplicate(original);
        if endpoint.duplicate_failure().is_some() {
            return Err(SelectedOpeningFailureV1::EndpointDuplicate);
        }

        self.custody_opening
            .open_once()
            .map_err(|_| SelectedOpeningFailureV1::Custody)?;
        let execution = self
            .custody_opening
            .admitted_execution()
            .ok_or(SelectedOpeningFailureV1::Local(
                SourceProviderSecurityError::Poisoned,
            ))?;
        self.carrier = Some(
            InertSourceProviderCarrierV1::adopt_selected(&mut self.socket, execution, endpoint)
                .map_err(|error| match error {
                    SelectedCarrierOpeningFailureV1::Source(error) => {
                        SelectedOpeningFailureV1::Local(error)
                    }
                    SelectedCarrierOpeningFailureV1::Socket(error) => {
                        SelectedOpeningFailureV1::Socket(error)
                    }
                })?,
        );

        // Each completed original moves directly into its destination before
        // the next clock or file/process observation. These takes do no I/O.
        self.provider_custody = self.custody_opening.take_provider_custody();
        self.root_mount_custody = self.custody_opening.take_root_mount_custody();
        let now = current_unix_seconds().map_err(SelectedOpeningFailureV1::Local)?;
        match (&mut self.provider_custody, &mut self.root_mount_custody) {
            (Some(custody), None) => custody.inner_mut().revalidate_at(now),
            (None, Some(custody)) => custody.inner_mut().revalidate_at(now),
            _ => Err(SourceProviderSecurityError::Poisoned),
        }
        .map_err(SelectedOpeningFailureV1::Local)
    }

    fn take_provider_parts(
        &mut self,
    ) -> Option<(ProtectedProviderCustodyV1, InertSourceProviderCarrierV1)> {
        if !self.attempted
            || self.ended
            || self.first_failure.is_some()
            || self.socket.is_some()
            || self.root_mount_custody.is_some()
            || self.provider_custody.is_none()
            || self.carrier.is_none()
        {
            return None;
        }

        match (self.provider_custody.take(), self.carrier.take()) {
            (Some(custody), Some(carrier)) => {
                self.armed = false;
                Some((custody, carrier))
            }
            (custody, carrier) => {
                self.provider_custody = custody;
                self.carrier = carrier;
                None
            }
        }
    }

    fn take_root_mount_parts(
        &mut self,
    ) -> Option<(ProtectedRootMountCustodyV1, InertSourceProviderCarrierV1)> {
        if !self.attempted
            || self.ended
            || self.first_failure.is_some()
            || self.socket.is_some()
            || self.provider_custody.is_some()
            || self.root_mount_custody.is_none()
            || self.carrier.is_none()
        {
            return None;
        }

        match (self.root_mount_custody.take(), self.carrier.take()) {
            (Some(custody), Some(carrier)) => {
                self.armed = false;
                Some((custody, carrier))
            }
            (custody, carrier) => {
                self.root_mount_custody = custody;
                self.carrier = carrier;
                None
            }
        }
    }

    fn shutdown_attempted(&self) -> bool {
        self.shutdown_attempted
            || self
                .endpoint
                .as_ref()
                .is_some_and(|endpoint| endpoint.shutdown_attempted())
    }

    fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.shutdown_failure.as_ref().or_else(|| {
            self.endpoint
                .as_ref()
                .and_then(|endpoint| endpoint.shutdown_failure())
        })
    }

    fn shutdown_unavailable(&self) -> bool {
        self.shutdown_unavailable
            || self
                .endpoint
                .as_ref()
                .is_some_and(|endpoint| endpoint.shutdown_unavailable())
    }

    fn close(&mut self) {
        if !self.ended {
            self.ended = true;
            let endpoint = self.endpoint.as_ref().filter(|endpoint| endpoint.retains_alias());
            if let Some(endpoint) = endpoint {
                endpoint.end_original();
                self.shutdown_attempted = endpoint.shutdown_attempted();
                self.shutdown_unavailable = endpoint.shutdown_unavailable();
            } else if let Some(socket) = self.socket.as_ref() {
                // A failed duplicate has no alias. The still-resident original
                // is used only to end its queue, never as a fallback transport.
                match socket.as_fd() {
                    Ok(original) => {
                        self.shutdown_attempted = true;
                        self.shutdown_failure =
                            rustix::net::shutdown(original, rustix::net::Shutdown::Both)
                                .err()
                                .map(std::io::Error::from);
                    }
                    Err(_) => self.shutdown_unavailable = true,
                }
            } else {
                self.shutdown_unavailable = true;
            }
        }

        if let Some(socket) = self.socket.as_mut() {
            socket.close();
        }
        if let Some(carrier) = self.carrier.as_mut() {
            carrier.close();
        }
        if let Some(custody) = self.provider_custody.as_mut() {
            custody.inner_mut().poison();
        }
        if let Some(custody) = self.root_mount_custody.as_mut() {
            custody.inner_mut().poison();
        }
    }
}

impl Drop for SelectedHandshakeOpeningV1 {
    fn drop(&mut self) {
        if self.armed {
            self.close();
        }
    }
}

/// Carries a provider outcome after exact AOSSPL persistence.
pub struct CommittedProviderOutcomeV1 {
    pub(super) transaction_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) artifact_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) reservation_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) response_sequence: u64,
    pub(super) method: aos_sandbox_source_provider_protocol::SourceProviderMethod,
    pub(super) session_binding: aos_sandbox_core::ObjectDigest,
    pub(super) committed_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pub(super) response: Option<Vec<u8>>,
    pub(super) send_attempted: Cell<bool>,
}

impl CommittedProviderOutcomeV1 {
    /// Returns the sealed routing binding without granting send authority.
    #[must_use]
    pub const fn session_binding(&self) -> aos_sandbox_core::ObjectDigest {
        self.session_binding
    }

    fn claim_send_attempt(&self) -> Result<(), crate::SourceProviderSecurityError> {
        claim_committed_send_attempt(&self.send_attempted)
    }
}

// Keeping sealed bytes borrowed does not make their move-only send authority
// repeatable. This bit records only an attempt, never receipt or Root ACK.
fn claim_committed_send_attempt(
    attempted: &Cell<bool>,
) -> Result<(), crate::SourceProviderSecurityError> {
    if attempted.replace(true) {
        return Err(crate::SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

#[cfg(test)]
mod committed_send_attempt_tests {
    use super::*;

    #[test]
    fn borrowed_send_attempt_cannot_be_rearmed_after_success_or_failure() {
        // This exercises the actual in-memory attempt primitive, not a fake
        // sealed outcome or a native observation authority constructor.
        let attempted = Cell::new(false);

        claim_committed_send_attempt(&attempted).unwrap();
        assert!(claim_committed_send_attempt(&attempted).is_err());
        assert!(claim_committed_send_attempt(&attempted).is_err());
        assert!(attempted.get());
    }
}

/// Proves one exact response was durably completed under Provider deadline checks.
///
/// The move-only value has no public constructor or scalar accessors. Mount may
/// consume it only while reauthenticating the same response against its exact
/// protected historical attempt.
pub struct PersistedProviderOutcomeV1 {
    pub(super) method: aos_sandbox_source_provider_protocol::SourceProviderMethod,
    pub(super) signed_request_digest: [u8; 32],
    pub(super) response_digest: [u8; 32],
    pub(super) completed_at_seconds: i64,
    pub(super) deadline_seconds: i64,
}

impl core::fmt::Debug for PersistedProviderOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PersistedProviderOutcomeV1([protected completion])")
    }
}

/// Retains a provider request verified against live protected session custody.
///
/// The non-cloneable value classifies a request but grants no journal
/// mutation, backend effect, signing, or response-send authority.
pub struct CurrentProviderRequestV1 {
    pub(super) verified: aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1,
    pub(super) provider_process_id: u32,
    pub(super) provider_start_time_ticks: u64,
}

/// Authorizes purpose-specific signing for one exact current admitted request.
///
/// The move-only value has no public constructor or scalar accessors. It is
/// minted only while live custody verifies a request and grants neither
/// journal mutation nor response-send authority.
pub struct ProviderOutcomeAuthorizationV1 {
    pub(super) method: aos_sandbox_source_provider_protocol::SourceProviderMethod,
    pub(super) request_id: [u8; 16],
    pub(super) signed_request_digest: aos_sandbox_core::ObjectDigest,
    pub(super) typed_request_digest: aos_sandbox_core::ObjectDigest,
    pub(super) attempt_digest: aos_sandbox_core::ObjectDigest,
    pub(super) operation_intent_digest: aos_sandbox_core::ObjectDigest,
    pub(super) provider: aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    pub(super) holder: aos_sandbox_source_provider_protocol::SourceProviderAuthorityV1,
    pub(super) session_binding: aos_sandbox_core::ObjectDigest,
    pub(super) provider_process_instance: [u8; 16],
    pub(super) acquisition_id: Option<aos_sandbox_core::ObjectDigest>,
    pub(super) lease_id: Option<[u8; 16]>,
    pub(super) lease_digest: Option<aos_sandbox_core::ObjectDigest>,
    pub(super) response_sequence: u64,
    pub(super) request_deadline_seconds: i64,
    pub(super) current_valid_until_seconds: i64,
    pub(super) journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
    pub(super) reservation_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) attempt_key_commitment: aos_sandbox_core::ObjectDigest,
    pub(super) claimed_purposes: Cell<u8>,
}

impl core::fmt::Debug for CommittedProviderOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CommittedProviderOutcomeV1([redacted])")
    }
}

impl core::fmt::Debug for CurrentProviderRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CurrentProviderRequestV1([redacted])")
    }
}

impl core::fmt::Debug for ProviderOutcomeAuthorizationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProviderOutcomeAuthorizationV1([redacted])")
    }
}

impl CurrentProviderRequestV1 {
    /// Borrows the authenticated protocol request for owner-side admission.
    #[must_use]
    pub const fn verified(
        &self,
    ) -> &aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1 {
        &self.verified
    }

    /// Returns the live-custody provider process identity retained for recovery fencing.
    ///
    /// The scalar projection grants no death, journal, effect, or signing
    /// authority. A later same-boot death proof is minted only by security
    /// custody after checking the exact protected session record.
    #[must_use]
    pub const fn provider_execution_identity(&self) -> (u32, u64) {
        (self.provider_process_id, self.provider_start_time_ticks)
    }

    /// Consumes this request only after its exact reservation is current.
    ///
    /// The protected snapshot binds the resulting one-shot authorization to
    /// one journal instance, the closed SourceProvider namespace, and its
    /// current sequence. `attempt_key` and `attempt_record` must still be the
    /// exact materialized reservation, whose canonical tail is the request
    /// authenticated by this value.
    ///
    /// # Errors
    ///
    /// Returns [`crate::SourceProviderSecurityError`] when protected journal
    /// authority is stale, the reservation differs, or a sentinel is present.
    pub(super) fn authorize_reserved(
        self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        journal_snapshot: aos_sandbox::ProtectedJournalSnapshot,
        attempt_key: &[u8],
        attempt_record: &[u8],
        response_sequence: u64,
    ) -> Result<ProviderOutcomeAuthorizationV1, crate::SourceProviderSecurityError> {
        use aos_sandbox_source_provider_protocol::{
            SourceProviderMethod, VerifiedProviderRequestV1, digest_acquire_request,
            digest_inventory_request, digest_release_request,
        };

        journal
            .validate_source_provider_authority_snapshot(&journal_snapshot)
            .map_err(|_| crate::SourceProviderSecurityError::SessionContinuity)?;
        let signed_request = authorization_signed_request(&self.verified);
        let projection = match &self.verified {
            VerifiedProviderRequestV1::Acquire(value) => value.ingress_projection(),
            VerifiedProviderRequestV1::Release(value) => value.ingress_projection(),
            VerifiedProviderRequestV1::Inventory(value) => value.ingress_projection(),
        };
        let (
            method,
            request_id,
            signed_request_digest,
            typed_request_digest,
            operation_intent_digest,
            attempt_digest,
            request_sequence,
            deadline_seconds,
            acquisition_sequence,
        ) = match &self.verified {
            VerifiedProviderRequestV1::Acquire(value) => (
                SourceProviderMethod::Acquire,
                value.request().request_id(),
                value.attempt().signed_request_digest(),
                digest_acquire_request(value.request()),
                value.acquire_intent_digest(),
                value.attempt().attempt_digest(),
                value.request().sequence(),
                value.request().deadline_seconds(),
                Some(value.request().acquisition_sequence()),
            ),
            VerifiedProviderRequestV1::Release(value) => (
                SourceProviderMethod::Release,
                value.request().request_id(),
                value.attempt().signed_request_digest(),
                digest_release_request(value.request()),
                value.release_intent_digest(),
                value.attempt().attempt_digest(),
                value.request().sequence(),
                value.request().deadline_seconds(),
                None,
            ),
            VerifiedProviderRequestV1::Inventory(value) => (
                SourceProviderMethod::Inventory,
                value.request().request_id(),
                value.attempt().signed_request_digest(),
                digest_inventory_request(value.request()),
                value.inventory_intent_digest(),
                value.attempt().attempt_digest(),
                value.request().sequence(),
                value.request().deadline_seconds(),
                Some(0),
            ),
        };
        let reserved_attempt =
            match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                attempt_key,
                attempt_record,
            ) {
                Ok(
                    aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Attempt(
                        attempt,
                    ),
                ) => attempt,
                _ => return Err(crate::SourceProviderSecurityError::SessionContinuity),
            };
        let authority_key = aos_sandbox_source_provider_ledger::ledger::format::authority_key(
            projection.provider_authority().authority_id(),
        );
        let authority = journal
            .get(&authority_key)
            .ok()
            .flatten()
            .and_then(|bytes| {
                match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                    &authority_key,
                    bytes,
                ) {
                    Ok(
                        aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Authority(
                            value,
                        ),
                    ) => Some(value),
                    _ => None,
                }
            })
            .ok_or(crate::SourceProviderSecurityError::SessionContinuity)?;
        let session_key = aos_sandbox_source_provider_ledger::ledger::format::session_key(
            projection.provider_authority().authority_id(),
            projection.root_mount_authority().authority_id(),
        );
        let session = journal
            .get(&session_key)
            .ok()
            .flatten()
            .and_then(|bytes| {
                match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                    &session_key,
                    bytes,
                ) {
                    Ok(
                        aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Session(
                            value,
                        ),
                    ) => Some(value),
                    _ => None,
                }
            })
            .ok_or(crate::SourceProviderSecurityError::SessionContinuity)?;
        let retained_release_acquisition_sequence = match &self.verified {
            VerifiedProviderRequestV1::Release(value) => {
                let key = aos_sandbox_source_provider_ledger::ledger::format::acquisition_key(
                    &aos_sandbox_source_provider_ledger::ledger::model::AcquisitionKeyV1 {
                        provider_id: projection.provider_authority().authority_id(),
                        holder_id: projection.root_mount_authority().authority_id(),
                        acquisition_id: value.request().acquisition_id(),
                    },
                );
                journal
                    .get(&key)
                    .ok()
                    .flatten()
                    .and_then(|bytes| {
                        match aos_sandbox_source_provider_ledger::ledger::format::decode_record(
                            &key, bytes,
                        ) {
                            Ok(
                                aos_sandbox_source_provider_ledger::ledger::model::DecodedRecordV1::Acquisition(
                                    acquisition,
                                ),
                            ) => Some(acquisition.acquisition_sequence),
                            _ => None,
                        }
                    })
            }
            _ => None,
        };
        if response_sequence == 0
            || attempt_key.is_empty()
            || attempt_record.is_empty()
            || reserved_attempt.state
                != aos_sandbox_source_provider_ledger::ProviderAttemptStateV1::Reserved
            || reserved_attempt.status.is_some()
            || reserved_attempt.method != method
            || reserved_attempt.request_id != request_id
            || reserved_attempt.signed_request != signed_request
            || reserved_attempt.signed_request_digest != signed_request_digest
            || reserved_attempt.signed_request_digest_again
                != reserved_attempt.signed_request_digest
            || reserved_attempt.typed_request_digest != typed_request_digest
            || reserved_attempt.operation_intent_digest != operation_intent_digest
            || reserved_attempt.attempt_digest != attempt_digest
            || reserved_attempt.request_sequence != request_sequence
            || reserved_attempt.deadline_seconds != deadline_seconds
            || acquisition_sequence
                .is_some_and(|sequence| reserved_attempt.acquisition_sequence != sequence)
            || (method == SourceProviderMethod::Release
                && retained_release_acquisition_sequence
                    != Some(reserved_attempt.acquisition_sequence))
            || reserved_attempt.provider != *projection.provider_authority()
            || reserved_attempt.holder != *projection.root_mount_authority()
            || reserved_attempt.root_record_signer != projection.ordered_signers()[1]
            || reserved_attempt.session_binding != projection.session_binding()
            || reserved_attempt.root_process_instance != projection.root_mount_process_instance()
            || reserved_attempt.provider_process_instance != projection.provider_process_instance()
            || reserved_attempt.signer_set_commitment != projection.signer_set_commitment()
            || reserved_attempt.proof_class_capabilities != projection.proof_class_capabilities()
            || reserved_attempt.supports_recursive != projection.supports_recursive()
            || reserved_attempt.supports_kernel_coupled != projection.supports_kernel_coupled()
            || reserved_attempt.verified_at_seconds != projection.verified_at_seconds()
            || reserved_attempt.current_valid_until_seconds
                != projection.current_valid_until_seconds()
            || reserved_attempt.completed_response.len() != 0
            || reserved_attempt.response_sequence.is_some()
            || reserved_attempt.response_digest.is_some()
            || reserved_attempt.result_digest.is_some()
            || authority.provider != *projection.provider_authority()
            || authority.trust_generation != projection.trust_generation()
            || authority.trust_digest != projection.trust_digest()
            || authority.revocation_generation != projection.revocation_generation()
            || authority.revocation_digest != projection.revocation_digest()
            || authority.route_id != projection.route_id()
            || authority.route_generation != projection.route_generation()
            || authority.route_digest != projection.route_digest()
            || authority.resource_namespace_digest != projection.resource_namespace_digest()
            || authority.proof_class_capabilities != projection.proof_class_capabilities()
            || authority.supports_recursive != projection.supports_recursive()
            || authority.supports_kernel_coupled != projection.supports_kernel_coupled()
            || projection.verified_at_seconds() < authority.valid_from_seconds
            || projection.current_valid_until_seconds() > authority.valid_until_seconds
            || session.provider != *projection.provider_authority()
            || session.holder != *projection.root_mount_authority()
            || session.session_binding != projection.session_binding()
            || session.root_process_instance != projection.root_mount_process_instance()
            || session.provider_process_instance != projection.provider_process_instance()
            || session.root_writer.uid != projection.actual_writer_root_mount_process().uid()
            || session.root_writer.gid != projection.actual_writer_root_mount_process().gid()
            || session.root_writer.tgid != projection.actual_writer_root_mount_process().tgid()
            || session.root_writer.start_time_ticks
                != projection
                    .actual_writer_root_mount_process()
                    .start_time_ticks()
            || session.root_writer.cgroup_digest
                != projection
                    .actual_writer_root_mount_process()
                    .cgroup_digest()
            || session.route_id != projection.route_id()
            || session.route_generation != projection.route_generation()
            || session.route_digest != projection.route_digest()
            || session.resource_namespace_digest != projection.resource_namespace_digest()
            || session.trust_generation != projection.trust_generation()
            || session.trust_digest != projection.trust_digest()
            || session.revocation_generation != projection.revocation_generation()
            || session.revocation_digest != projection.revocation_digest()
            || session.signers != *projection.ordered_signers()
            || session.signer_set_commitment != projection.signer_set_commitment()
            || session.root_hello_digest != projection.root_mount_hello_digest()
            || session.provider_hello_digest != projection.provider_hello_digest()
            || session.root_hello != projection.signed_root_mount_hello().to_canonical_bytes()
            || session.provider_hello != projection.signed_provider_hello().to_canonical_bytes()
            || session.pending_attempt_digest != Some(attempt_digest)
            || session.next_response_sequence != response_sequence
            || journal
                .validate_source_provider_authority_snapshot(&journal_snapshot)
                .is_err()
            || journal.get(attempt_key).ok().flatten() != Some(attempt_record)
        {
            return Err(crate::SourceProviderSecurityError::SessionContinuity);
        }
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"aos.sandbox.source-provider.protected-reservation.v1\0");
        hasher.update((attempt_key.len() as u32).to_be_bytes());
        hasher.update(attempt_key);
        hasher.update((attempt_record.len() as u32).to_be_bytes());
        hasher.update(attempt_record);
        let reservation_commitment =
            aos_sandbox_core::ObjectDigest::from_bytes(hasher.finalize().into());
        let attempt_key_commitment = {
            let mut hasher = Sha256::new();
            hasher.update(b"aos.sandbox.source-provider.protected-attempt-key.v1\0");
            hasher.update((attempt_key.len() as u32).to_be_bytes());
            hasher.update(attempt_key);
            aos_sandbox_core::ObjectDigest::from_bytes(hasher.finalize().into())
        };

        let authorization = match &self.verified {
            VerifiedProviderRequestV1::Acquire(value) => ProviderOutcomeAuthorizationV1 {
                method: SourceProviderMethod::Acquire,
                request_id: value.request().request_id(),
                signed_request_digest: value.attempt().signed_request_digest(),
                typed_request_digest: digest_acquire_request(value.request()),
                attempt_digest: value.attempt().attempt_digest(),
                operation_intent_digest: value.acquire_intent_digest(),
                provider: value.ingress_projection().provider_authority().clone(),
                holder: value.ingress_projection().root_mount_authority().clone(),
                session_binding: value.session_binding(),
                provider_process_instance: value.provider_process_instance(),
                acquisition_id: Some(value.request().acquisition_id()),
                lease_id: None,
                lease_digest: None,
                response_sequence,
                request_deadline_seconds: value.request().deadline_seconds(),
                current_valid_until_seconds: value
                    .ingress_projection()
                    .current_valid_until_seconds(),
                journal_snapshot,
                reservation_commitment,
                attempt_key_commitment,
                claimed_purposes: Cell::new(0),
            },
            VerifiedProviderRequestV1::Release(value) => ProviderOutcomeAuthorizationV1 {
                method: SourceProviderMethod::Release,
                request_id: value.request().request_id(),
                signed_request_digest: value.attempt().signed_request_digest(),
                typed_request_digest: digest_release_request(value.request()),
                attempt_digest: value.attempt().attempt_digest(),
                operation_intent_digest: value.release_intent_digest(),
                provider: value.ingress_projection().provider_authority().clone(),
                holder: value.ingress_projection().root_mount_authority().clone(),
                session_binding: value.session_binding(),
                provider_process_instance: value.provider_process_instance(),
                acquisition_id: Some(value.request().acquisition_id()),
                lease_id: Some(value.request().lease_id()),
                lease_digest: Some(value.request().lease_digest()),
                response_sequence,
                request_deadline_seconds: value.request().deadline_seconds(),
                current_valid_until_seconds: value
                    .ingress_projection()
                    .current_valid_until_seconds(),
                journal_snapshot,
                reservation_commitment,
                attempt_key_commitment,
                claimed_purposes: Cell::new(0),
            },
            VerifiedProviderRequestV1::Inventory(value) => ProviderOutcomeAuthorizationV1 {
                method: SourceProviderMethod::Inventory,
                request_id: value.request().request_id(),
                signed_request_digest: value.attempt().signed_request_digest(),
                typed_request_digest: digest_inventory_request(value.request()),
                attempt_digest: value.attempt().attempt_digest(),
                operation_intent_digest: value.inventory_intent_digest(),
                provider: value.ingress_projection().provider_authority().clone(),
                holder: value.ingress_projection().root_mount_authority().clone(),
                session_binding: value.session_binding(),
                provider_process_instance: value.provider_process_instance(),
                acquisition_id: None,
                lease_id: None,
                lease_digest: None,
                response_sequence,
                request_deadline_seconds: value.request().deadline_seconds(),
                current_valid_until_seconds: value
                    .ingress_projection()
                    .current_valid_until_seconds(),
                journal_snapshot,
                reservation_commitment,
                attempt_key_commitment,
                claimed_purposes: Cell::new(0),
            },
        };
        Ok(authorization)
    }
}

impl ProviderOutcomeAuthorizationV1 {
    pub(super) fn claim_purpose(
        &self,
        purpose: u8,
    ) -> Result<(), crate::SourceProviderSecurityError> {
        let claimed = self.claimed_purposes.get();
        if purpose == 0 || claimed & purpose != 0 {
            return Err(crate::SourceProviderSecurityError::SessionContinuity);
        }
        self.claimed_purposes.set(claimed | purpose);
        Ok(())
    }
}

fn authorization_signed_request<'request>(
    verified: &'request aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1,
) -> &'request [u8] {
    use aos_sandbox_source_provider_protocol::VerifiedProviderRequestV1;
    match verified {
        VerifiedProviderRequestV1::Acquire(value) => value.attempt().canonical_signed_request(),
        VerifiedProviderRequestV1::Release(value) => value.attempt().canonical_signed_request(),
        VerifiedProviderRequestV1::Inventory(value) => value.attempt().canonical_signed_request(),
    }
}

pub(super) enum HandshakeTransitionV1<RetryState, CompleteState> {
    Complete(CompleteState),
    Retry(RetryState),
    Fatal(crate::SourceProviderSecurityError),
}

pub(super) fn current_unix_seconds() -> Result<i64, crate::SourceProviderSecurityError> {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
    if value < 0 {
        Err(crate::SourceProviderSecurityError::ExecutionChanged)
    } else {
        Ok(value)
    }
}

pub(super) fn process_identity(
    evidence: &crate::execution::ProcessExecutionEvidenceV1,
) -> Result<
    aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1,
    crate::SourceProviderSecurityError,
> {
    let credentials = evidence.credentials();
    aos_sandbox_source_provider_protocol::SourceProviderProcessIdentityV1::new(
        credentials.effective_user_id(),
        credentials.effective_group_id(),
        evidence.tgid(),
        evidence.start_time_ticks(),
        crate::execution::cgroup_object_digest(evidence.cgroup_path_digest()),
        evidence.is_alive()?,
    )
    .map_err(|_| crate::SourceProviderSecurityError::SessionContinuity)
}
