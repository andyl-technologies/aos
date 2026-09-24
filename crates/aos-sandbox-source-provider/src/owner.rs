//! Fixed-root SourceProvider journal and live-session ownership.
//!
//! The owner is the public construction boundary for provider runtime state.
//! It fixes protected custody, journal, and backend-verifier paths and the
//! namespace, retains the journal lock, drives one caller-supplied connected
//! socket through the sealed security handshake, and lends the resulting
//! ledger only under the same live claim.

use std::path::Path;
use std::sync::Arc;

use aos_sandbox::{Journal, JournalLimits, RecordNamespace, RecoveryReport};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_protocol::{
    CatalogCurrentnessQueryV1, InventoryReadbackQueryV1, RecoveryCurrentnessQueryV1,
    SignedCatalogCurrentnessV1, SignedSourceProviderRequestV1, SourceProviderMethod,
    decode_acquire_request, decode_inventory_request,
};
use aos_sandbox_source_provider_security::{
    ProviderSourceProviderHandshakeStatusV1, ProviderSourceProviderOwnerV1,
};

use crate::state::{DetachedProviderLedgerV1, ProtectedProviderConfigurationV1};
use crate::{DurableProviderReplyV1, ProviderLedgerError, ProviderLedgerLimits, ProviderLedgerV1};
use sha2::{Digest as _, Sha256};

const FIXED_PROVIDER_STATE_ROOT: &str = "/var/lib/aos/source-provider";
const FIXED_PROVIDER_JOURNAL: &str = "provider.journal";
const CANONICAL_CATALOG_PUBLICATION_BYTES: usize = 520;

enum FixedProviderOwnerStateV1 {
    Handshake {
        security: ProviderSourceProviderOwnerV1,
        canonical_catalog_publication: Vec<u8>,
    },
    MigrationRequired {
        session: aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        canonical_catalog_publication: Vec<u8>,
    },
    MigrationRecovery {
        session: aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        canonical_catalog_publication: Vec<u8>,
        recovery: crate::migration::AossplMigrationRecoveryV1,
    },
    Ready(DetachedProviderLedgerV1),
}

struct PendingCatalogCurrentnessV1 {
    query: CatalogCurrentnessQueryV1,
    response: SignedCatalogCurrentnessV1,
    current_catalog: aos_sandbox_source_provider_security::ProtectedCurrentCatalogPublicationV1,
}

/// Reports one non-effect catalog control exchange step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedProviderCatalogProgressV1 {
    /// No complete challenge or send capacity was available yet.
    Pending,
    /// One exact current-head response was sent to Root Mount.
    Replied,
}

/// Retains a source-method packet received from the live authenticated carrier.
///
/// The private field prevents callers from substituting arbitrary request
/// bytes before the fixed reducer performs full signature and sequence checks.
pub struct FixedProviderAuthenticatedSourceRequestV1 {
    signed: SignedSourceProviderRequestV1,
}

impl core::fmt::Debug for FixedProviderAuthenticatedSourceRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedProviderAuthenticatedSourceRequestV1([retained packet])")
    }
}

impl FixedProviderAuthenticatedSourceRequestV1 {
    pub(crate) fn into_signed(self) -> SignedSourceProviderRequestV1 {
        self.signed
    }
}

/// Classifies one retained packet without admitting a source effect.
#[derive(Debug)]
pub enum FixedProviderIngressProgressV1 {
    /// The nonblocking carrier has no complete packet or pending send capacity.
    Pending,
    /// An exact protected catalog-currentness response was sent.
    CatalogReplied,
    /// A new authenticated carrier asks about one protected original attempt.
    Recovery(RecoveryCurrentnessQueryV1),
    /// A new authenticated carrier asks for an old protected Inventory result.
    InventoryReadback(InventoryReadbackQueryV1),
    /// A kernel-coupled Acquire or holder Inventory awaits protected admission.
    Source(FixedProviderAuthenticatedSourceRequestV1),
}

/// Reports exact protected replay performed by the fixed provider owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedProviderOpenReportV1 {
    /// Reports structural replay and any safe partial-tail truncation.
    pub journal: RecoveryReport,
}

/// Classifies one exact replay-validated Mount request after joint restart.
#[must_use = "cold request readback must be consumed"]
#[derive(Debug)]
pub enum FixedProviderRequestReadbackV1 {
    /// Mount must issue a fresh current-session retry for the exact request.
    RetryAuthorized(ProtectedProviderMountRetryAuthorityV1),
    /// An exact historical descriptor-free outcome can be reauthenticated.
    HistoricalOutcome(FixedProviderHistoricalOutcomeV1),
    /// An exact completed Acquire must reopen its active SourceRoot first.
    AcquireReopen(FixedProviderAcquireReopenV1),
    /// Provider durably retains effect/recovery work for the request.
    RecoveryPending,
}

/// Owns one replay-validated historical outcome and optional reopened root.
///
/// The value has no public constructor. Its bytes and descriptor are not
/// authoritative until Mount reauthenticates them against the exact protected
/// attempt and historical session records.
pub struct FixedProviderHistoricalOutcomeV1 {
    pub(crate) response: Vec<u8>,
    pub(crate) source_root: Option<crate::ProviderPhysicalSourceRootV1>,
    pub(crate) persisted: aos_sandbox_source_provider_security::PersistedProviderOutcomeV1,
}

impl core::fmt::Debug for FixedProviderHistoricalOutcomeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedProviderHistoricalOutcomeV1([protected outcome])")
    }
}

impl FixedProviderHistoricalOutcomeV1 {
    /// Consumes the outcome into Mount's protected historical verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if an included SourceRoot no longer has the exact
    /// protected physical identity captured by Provider.
    #[doc(hidden)]
    pub fn into_security_parts(
        self,
    ) -> Result<
        (
            Vec<u8>,
            Option<aos_sandbox_source_provider_security::ProviderSourceRootHandoffV1>,
            aos_sandbox_source_provider_security::PersistedProviderOutcomeV1,
        ),
        ProviderLedgerError,
    > {
        let source_root = self
            .source_root
            .map(crate::ProviderPhysicalSourceRootV1::into_security_handoff)
            .transpose()?;
        Ok((self.response, source_root, self.persisted))
    }
}

/// Authorizes one demand-driven reopen of an exact completed Acquire.
///
/// This value is move-only and has no public constructor. Only the fixed
/// backend session can consume it.
pub struct FixedProviderAcquireReopenV1 {
    pub(crate) replay: crate::DurableAcquireReplayV1,
    pub(crate) persisted: aos_sandbox_source_provider_security::PersistedProviderOutcomeV1,
}

impl core::fmt::Debug for FixedProviderAcquireReopenV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedProviderAcquireReopenV1([protected replay])")
    }
}

/// Authorizes Mount to retry one exact provider recovery or proven-absent request.
///
/// The type has no public constructor and is consumed by Mount's protected
/// AOSMSA02 transition. It carries identity only; effect and signing authority
/// remain in their fixed owners.
pub struct ProtectedProviderMountRetryAuthorityV1 {
    method: aos_sandbox_source_provider_protocol::SourceProviderMethod,
    provider_acquisition_id: Option<[u8; 32]>,
    signed_request_digest: [u8; 32],
}

impl core::fmt::Debug for ProtectedProviderMountRetryAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProtectedProviderMountRetryAuthorityV1([protected selection])")
    }
}

impl ProtectedProviderMountRetryAuthorityV1 {
    /// Consumes the authority into its exact nonauthorizing identity projection.
    #[doc(hidden)]
    pub fn into_identity(
        self,
    ) -> (
        aos_sandbox_source_provider_protocol::SourceProviderMethod,
        Option<[u8; 32]>,
        [u8; 32],
    ) {
        (
            self.method,
            self.provider_acquisition_id,
            self.signed_request_digest,
        )
    }
}

/// Reports whether the fixed provider owner is ready to lend its ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedProviderOwnerStatusV1 {
    /// The nonblocking authenticated hello exchange remains pending.
    HandshakePending,
    /// The exact legacy graph requires authenticated supplemental provenance.
    MigrationRequired,
    /// An ambiguous migration append is retained for fixed-owner readback.
    MigrationRecoveryRequired,
    /// The fixed journal, configuration, and live session are current.
    Ready,
}

/// Preserves a Mount migration recovery token across owner-acquisition failure.
#[must_use = "Mount migration recovery authority must be retried or reconciled"]
pub enum FixedMountStateMigrationRecoveryOutcomeV2 {
    /// Contains the security-validated install/readback result.
    Resolved(aos_sandbox_source_provider_security::MountSourceStateMigrationInstallOutcomeV2),
    /// Retains the exact recovery token because a fixed owner could not be borrowed.
    RetryRequired {
        /// Reports the fixed-owner acquisition failure.
        error: ProviderLedgerError,
        /// Retains the authenticated migration authority for another attempt.
        recovery: aos_sandbox_source_provider_security::MountSourceStateMigrationRecoveryV2,
    },
}

/// Owns the fixed provider custody, journal lock, and current session state.
///
/// This dormant type creates no listener, socket path, backend, route
/// advertisement, feature activation, or dispatch loop. The caller supplies an
/// already-connected descriptor-subject socket, while protected custody,
/// journal, and backend-verifier locations are compiled in and cannot be
/// redirected.
pub struct FixedProviderOwnerV1 {
    journal: Option<Journal>,
    state: Option<FixedProviderOwnerStateV1>,
    backend_verifier: Arc<crate::backend_verifier::ProtectedBackendVerifierV1>,
    recovery_handshake: Option<(
        ProviderSourceProviderOwnerV1,
        DetachedProviderLedgerV1,
        Option<aos_sandbox_source_provider_security::DeadProviderExecutionV1>,
    )>,
    ingress_reopen: Option<(
        aos_sandbox_source_provider_security::ProviderIngressReopenCheckpointV1,
        DetachedProviderLedgerV1,
        Option<aos_sandbox_source_provider_security::DeadProviderExecutionV1>,
    )>,
    pub(crate) pending_backend_recovery:
        Vec<crate::backend_adapter::FixedProviderBackendRecoveryV1>,
    pub(crate) priority_mount_retry_digest: Option<[u8; 32]>,
    pub(crate) priority_mount_retry_rearm_digest: Option<[u8; 32]>,
    pending_catalog_currentness: Option<PendingCatalogCurrentnessV1>,
    last_catalog_sequence: u64,
    last_catalog_minimum: Option<(u64, ObjectDigest)>,
    last_recovery_sequence: u64,
    pending_recovery_query_digest: Option<ObjectDigest>,
    pending_recovery_plan_digest: Option<ObjectDigest>,
    pending_inventory_readback_digest: Option<ObjectDigest>,
}

impl core::fmt::Debug for FixedProviderOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedProviderOwnerV1([protected owner])")
    }
}

impl FixedProviderOwnerV1 {
    /// Opens the fixed journal and begins an authenticated provider handshake.
    ///
    /// `canonical_catalog_publication` is nonauthorizing input. It is retained
    /// only until the live security session verifies its signature and exact
    /// protected trust, provider, route, namespace, and catalog continuity.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for an unsafe or locked fixed journal,
    /// invalid fixed provider custody or verifier manifest, or an invalid
    /// connected socket.
    pub fn open_fixed(
        socket: DescriptorSubjectSocket,
        canonical_catalog_publication: &[u8],
    ) -> Result<(Self, FixedProviderOpenReportV1), ProviderLedgerError> {
        if canonical_catalog_publication.len() != CANONICAL_CATALOG_PUBLICATION_BYTES {
            return Err(ProviderLedgerError::Corrupt(
                "canonical catalog publication length",
            ));
        }
        let (journal, recovery) = Journal::open_protected_at(
            Path::new(FIXED_PROVIDER_STATE_ROOT),
            FIXED_PROVIDER_JOURNAL,
            provider_journal_limits(),
        )?;
        let backend_verifier =
            Arc::new(crate::backend_verifier::ProtectedBackendVerifierV1::load_fixed()?);
        let security = ProviderSourceProviderOwnerV1::open_fixed(socket)?;
        Ok((
            Self {
                journal: Some(journal),
                state: Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication: canonical_catalog_publication.to_vec(),
                }),
                backend_verifier,
                recovery_handshake: None,
                ingress_reopen: None,
                pending_backend_recovery: Vec::new(),
                priority_mount_retry_digest: None,
                priority_mount_retry_rearm_digest: None,
                pending_catalog_currentness: None,
                last_catalog_sequence: 0,
                last_catalog_minimum: None,
                last_recovery_sequence: 0,
                pending_recovery_query_digest: None,
                pending_recovery_plan_digest: None,
                pending_inventory_readback_digest: None,
            },
            FixedProviderOpenReportV1 { journal: recovery },
        ))
    }

    /// Advances one owner-held handshake step and installs a current ledger.
    ///
    /// Retryable I/O leaves all custody and transcript state in this owner. On
    /// completion, the method verifies the catalog through current session
    /// custody, initializes or fully replays namespace 41, installs that exact
    /// session, and detaches only non-journal in-memory state.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for fatal handshake failure, catalog or
    /// configuration mismatch, malformed replay, or ambiguous initialization.
    pub fn advance_handshake(&mut self) -> Result<FixedProviderOwnerStatusV1, ProviderLedgerError> {
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let (mut security, canonical_catalog_publication) = match state {
            FixedProviderOwnerStateV1::Handshake {
                security,
                canonical_catalog_publication,
            } => (security, canonical_catalog_publication),
            FixedProviderOwnerStateV1::MigrationRequired {
                session,
                canonical_catalog_publication,
            } => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRequired {
                    session,
                    canonical_catalog_publication,
                });
                return Ok(FixedProviderOwnerStatusV1::MigrationRequired);
            }
            FixedProviderOwnerStateV1::MigrationRecovery {
                session,
                canonical_catalog_publication,
                recovery,
            } => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRecovery {
                    session,
                    canonical_catalog_publication,
                    recovery,
                });
                return Ok(FixedProviderOwnerStatusV1::MigrationRecoveryRequired);
            }
            FixedProviderOwnerStateV1::Ready(detached) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Ok(FixedProviderOwnerStatusV1::Ready);
            }
        };
        if security.advance_handshake()? == ProviderSourceProviderHandshakeStatusV1::Pending {
            self.state = Some(FixedProviderOwnerStateV1::Handshake {
                security,
                canonical_catalog_publication,
            });
            return Ok(FixedProviderOwnerStatusV1::HandshakePending);
        }

        let initial_authority = self
            .journal
            .as_mut()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        initial_authority.validate_fixed_source_provider_storage()?;
        let handoff = initial_authority.fixed_source_provider_session_handoff()?;
        let mut session = security.into_fixed_ledger_session(handoff)?;
        let first = open_claimed_ledger(
            initial_authority,
            &mut session,
            &canonical_catalog_publication,
        );
        let mut ledger = match first {
            Ok(ledger) => ledger,
            Err(_) => {
                self.reopen_fixed_journal()?;
                match open_ledger(
                    self.journal
                        .as_mut()
                        .ok_or(ProviderLedgerError::RuntimePoisoned)?,
                    &mut session,
                    &canonical_catalog_publication,
                ) {
                    Ok(ledger) => ledger,
                    Err(error) => {
                        self.reopen_fixed_journal()?;
                        match open_ledger(
                            self.journal
                                .as_mut()
                                .ok_or(ProviderLedgerError::RuntimePoisoned)?,
                            &mut session,
                            &canonical_catalog_publication,
                        ) {
                            Ok(ledger) => ledger,
                            Err(_) => {
                                self.reopen_fixed_journal()?;
                                match recover_existing_ledger(
                                    self.journal
                                        .as_mut()
                                        .ok_or(ProviderLedgerError::RuntimePoisoned)?,
                                    &mut session,
                                    &canonical_catalog_publication,
                                ) {
                                    Ok(Some(ledger)) => ledger,
                                    Ok(None) => return Err(error),
                                    Err(ProviderLedgerError::MigrationNeedsProvenance(_)) => {
                                        self.state =
                                            Some(FixedProviderOwnerStateV1::MigrationRequired {
                                                session,
                                                canonical_catalog_publication,
                                            });
                                        return Ok(FixedProviderOwnerStatusV1::MigrationRequired);
                                    }
                                    Err(recovery_error) => return Err(recovery_error),
                                }
                            }
                        }
                    }
                }
            }
        };
        ledger.install_current_session(session)?;
        let detached = ledger.detach();
        self.pending_backend_recovery =
            crate::backend_adapter::rehydrate_backend_recovery(&detached)?;
        self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
        Ok(FixedProviderOwnerStatusV1::Ready)
    }

    /// Runs one provider-ledger operation under the fixed namespace-41 claim.
    ///
    /// The closure cannot retain the ledger, journal authority, or live session
    /// beyond this borrow. In-memory pending capabilities are reclaimed even
    /// when the operation returns an error.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the owner is not ready, the fixed
    /// claim is unavailable, or `operation` rejects the current state.
    pub fn with_ledger<R>(
        &mut self,
        operation: impl for<'ledger> FnOnce(
            &mut ProviderLedgerV1<'ledger>,
        ) -> Result<R, ProviderLedgerError>,
    ) -> Result<R, ProviderLedgerError> {
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state @ (FixedProviderOwnerStateV1::MigrationRequired { .. }
            | FixedProviderOwnerStateV1::MigrationRecovery { .. }) => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider migration is not complete",
                ));
            }
            FixedProviderOwnerStateV1::Handshake {
                security,
                canonical_catalog_publication,
            } => {
                self.state = Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication,
                });
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider handshake is not current",
                ));
            }
        };
        let journal = match self.journal.as_mut() {
            Some(journal) => journal,
            None => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(ProviderLedgerError::RuntimePoisoned);
            }
        };
        let authority = match journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
            .and_then(|authority| {
                authority.validate_fixed_source_provider_storage()?;
                Ok(authority)
            }) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(error.into());
            }
        };
        let mut ledger = ProviderLedgerV1::attach(authority, detached);
        let result = operation(&mut ledger);
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
        result
    }

    pub(crate) fn backend_verifier(
        &self,
    ) -> Arc<crate::backend_verifier::ProtectedBackendVerifierV1> {
        Arc::clone(&self.backend_verifier)
    }

    /// Begins a same-carrier successor handshake for retained backend recovery.
    ///
    /// # Errors
    ///
    /// Returns an error unless exactly one unresolved recovery owns the fixed
    /// ingress session and has not yet accepted a fresh request.
    #[doc(hidden)]
    pub fn begin_recovery_successor_handshake(&mut self) -> Result<(), ProviderLedgerError> {
        let retained_recovery_is_not_ready =
            self.pending_backend_recovery
                .first()
                .is_some_and(|recovery| {
                    recovery.has_fresh_request() || recovery.successor_session_ready()
                });
        if self.recovery_handshake.is_some()
            || self.ingress_reopen.is_some()
            || (self.pending_backend_recovery.is_empty()
                && self.priority_mount_retry_rearm_digest.is_none())
            || retained_recovery_is_not_ready
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "provider recovery successor handshake is not ready",
            ));
        }
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let mut detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider ledger is not ready for recovery rotation",
                ));
            }
        };
        let (session, recovered_execution_death) = match detached.take_fixed_current_session() {
            Ok(session) => session,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(error);
            }
        };
        let security = session.into_successor_owner()?;
        self.recovery_handshake = Some((security, detached, recovered_execution_death));
        Ok(())
    }

    pub(crate) fn retain_failed_ingress(
        &mut self,
        checkpoint: aos_sandbox_source_provider_security::ProviderIngressReopenCheckpointV1,
    ) -> Result<(), ProviderLedgerError> {
        if self.ingress_reopen.is_some() || self.recovery_handshake.is_some() {
            return Err(ProviderLedgerError::InvalidTransition(
                "provider ingress reopen custody is already retained",
            ));
        }
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let mut detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider ledger is not ready for ingress reopen",
                ));
            }
        };
        let (poisoned, recovered_execution_death) = detached.take_fixed_current_session()?;
        drop(poisoned);
        self.ingress_reopen = Some((checkpoint, detached, recovered_execution_death));
        Ok(())
    }

    /// Installs a connected replacement carrier for retained fatal ingress custody.
    ///
    /// This starts only the dormant authenticated successor handshake. It does
    /// not create a socket, listener, service, or readiness signal.
    ///
    /// # Errors
    ///
    /// Returns an error unless fatal ingress custody is retained and the fixed
    /// protected Provider owner admits the connected replacement socket.
    #[doc(hidden)]
    pub fn reopen_failed_ingress(
        &mut self,
        socket: DescriptorSubjectSocket,
    ) -> Result<(), ProviderLedgerError> {
        if self.recovery_handshake.is_some() {
            return Err(ProviderLedgerError::InvalidTransition(
                "provider recovery handshake is already pending",
            ));
        }
        let (checkpoint, detached, recovered_execution_death) =
            self.ingress_reopen
                .take()
                .ok_or(ProviderLedgerError::InvalidTransition(
                    "provider fatal ingress reopen custody is absent",
                ))?;
        match ProviderSourceProviderOwnerV1::open_fixed_recovery(socket, checkpoint) {
            Ok(security) => {
                self.recovery_handshake = Some((security, detached, recovered_execution_death));
                Ok(())
            }
            Err((error, checkpoint)) => {
                self.ingress_reopen = Some((checkpoint, detached, recovered_execution_death));
                Err(error.into())
            }
        }
    }

    /// Reports whether fatal ingress requires an explicit replacement socket.
    #[must_use]
    #[doc(hidden)]
    pub const fn failed_ingress_reopen_required(&self) -> bool {
        self.ingress_reopen.is_some()
    }

    /// Advances one retained same-carrier recovery handshake step.
    ///
    /// # Errors
    ///
    /// Returns an error for absent recovery custody, failed authentication, or
    /// inability to install the successor beneath the fixed journal claim.
    #[doc(hidden)]
    pub fn advance_recovery_successor_handshake(
        &mut self,
    ) -> Result<FixedProviderOwnerStatusV1, ProviderLedgerError> {
        let (mut security, detached, recovered_execution_death) = self
            .recovery_handshake
            .take()
            .ok_or(ProviderLedgerError::InvalidTransition(
                "provider recovery successor handshake is absent",
            ))?;
        if security.advance_handshake()? == ProviderSourceProviderHandshakeStatusV1::Pending {
            self.recovery_handshake = Some((security, detached, recovered_execution_death));
            return Ok(FixedProviderOwnerStatusV1::HandshakePending);
        }

        let authority = self
            .journal
            .as_mut()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
        authority.validate_fixed_source_provider_storage()?;
        let handoff = authority.fixed_source_provider_session_handoff()?;
        let (session, supersession) = security.into_fixed_recovery_ledger_session(handoff)?;
        let mut ledger = ProviderLedgerV1::attach(authority, detached);
        ledger.install_recovery_successor_session(
            session,
            supersession,
            recovered_execution_death,
        )?;
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
        // Recovery query sequences are local to the authenticated carrier.
        self.last_recovery_sequence = 0;
        self.pending_recovery_query_digest = None;
        self.pending_recovery_plan_digest = None;
        self.pending_inventory_readback_digest = None;
        if let Some(recovery) = self.pending_backend_recovery.first_mut() {
            recovery.mark_successor_session_ready();
        }
        Ok(FixedProviderOwnerStatusV1::Ready)
    }

    /// Reports whether backend recovery currently owns the handshake carrier.
    #[doc(hidden)]
    pub fn recovery_successor_handshake_pending(&self) -> bool {
        self.recovery_handshake.is_some()
    }

    /// Reports whether retained recovery still needs a fresh authenticated packet.
    #[doc(hidden)]
    pub fn backend_recovery_awaits_fresh_request(&self) -> bool {
        !self.pending_backend_recovery.is_empty()
            && !self.pending_backend_recovery[0].has_fresh_request()
    }

    /// Reports whether backend recovery excludes unrelated provider traffic.
    #[doc(hidden)]
    pub fn backend_recovery_active(&self) -> bool {
        !self.pending_backend_recovery.is_empty()
            || self.recovery_handshake.is_some()
            || self.ingress_reopen.is_some()
    }

    /// Aligns Provider's recovery head with Mount's exact oldest request.
    ///
    /// All nonselected recovery work remains move-only in its original order.
    /// A false result means Provider has no unresolved effect for this request;
    /// fixed readback must classify it before Mount may retry.
    ///
    /// # Errors
    ///
    /// Returns an error if more than one retained work item claims the same
    /// exact signed request.
    #[doc(hidden)]
    pub fn align_backend_recovery_with_mount_request(
        &mut self,
        signed_request: &aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1,
    ) -> Result<bool, ProviderLedgerError> {
        let matching = self
            .pending_backend_recovery
            .iter()
            .enumerate()
            .filter_map(|(index, recovery)| {
                recovery
                    .matches_signed_request(signed_request)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let [index] = matching.as_slice() else {
            if matching.is_empty() {
                return Ok(false);
            }
            return Err(ProviderLedgerError::Equivocation);
        };
        if *index != 0 {
            let selected = self.pending_backend_recovery.remove(*index);
            self.pending_backend_recovery.insert(0, selected);
        }
        Ok(true)
    }

    /// Reports whether one exact Mount retry owns ingress ahead of recovery work.
    #[must_use]
    #[doc(hidden)]
    pub const fn mount_retry_priority_active(&self) -> bool {
        self.priority_mount_retry_digest.is_some()
    }

    /// Reports whether a rejected priority packet requires exact session rotation.
    #[must_use]
    #[doc(hidden)]
    pub const fn mount_retry_rearm_required(&self) -> bool {
        self.priority_mount_retry_rearm_digest.is_some()
    }

    /// Retains an exact Mount retry after fatal ingress closed the carrier.
    ///
    /// # Errors
    ///
    /// Returns an error unless failed ingress reopen is pending and detached
    /// state proves either no Provider reservation crossed the failed receive
    /// or the sole reservation and retained backend-recovery head are this
    /// exact uncompleted request. Only the no-reservation case arms the
    /// pre-effect priority lane.
    #[doc(hidden)]
    pub fn arm_mount_retry_after_failed_ingress(
        &mut self,
        signed_request: aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1,
    ) -> Result<(), ProviderLedgerError> {
        if self.ingress_reopen.is_none() {
            return Err(ProviderLedgerError::InvalidTransition(
                "provider ingress is not awaiting reopen",
            ));
        }
        let digest = *aos_sandbox_source_provider_protocol::digest_signed_request(&signed_request)
            .as_bytes();
        let detached = &self
            .ingress_reopen
            .as_ref()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?
            .1;
        let reserved_attempts = detached
            .recovered()
            .attempts
            .values()
            .filter(|attempt| attempt.state == crate::ProviderAttemptStateV1::Reserved)
            .collect::<Vec<_>>();
        let matching_attempts = reserved_attempts
            .iter()
            .filter(|attempt| {
                attempt.state == crate::ProviderAttemptStateV1::Reserved
                    && attempt.signed_request_digest.as_bytes() == &digest
                    && attempt.signed_request == signed_request.to_canonical_bytes()
            })
            .count();
        // No retained reservation means the fatal record receive crossed no
        // Provider effect. Otherwise the sole reservation must be this exact
        // request; another outstanding attempt cannot be displaced.
        if matching_attempts > 1
            || (matching_attempts == 0 && !reserved_attempts.is_empty())
            || (matching_attempts == 1 && reserved_attempts.len() != 1)
        {
            return Err(ProviderLedgerError::Equivocation);
        }

        if matching_attempts == 1 {
            if self.priority_mount_retry_digest.is_some()
                || self.priority_mount_retry_rearm_digest.is_some()
                || !self.align_backend_recovery_with_mount_request(&signed_request)?
            {
                return Err(ProviderLedgerError::InvalidTransition(
                    "reserved failed-ingress request lacks exact backend recovery custody",
                ));
            }
            return Ok(());
        }

        self.priority_mount_retry_digest = None;
        self.priority_mount_retry_rearm_digest = Some(digest);
        Ok(())
    }

    /// Reads the exact durable disposition of one signed Mount request.
    ///
    /// Retry authority is returned only after replay validation under the fixed
    /// journal claim. A completed descriptor-free response is returned as an
    /// opaque historical outcome, while Complete Acquire returns a move-only
    /// physical-reopen authority. Historical response bytes are never replayed
    /// as an old-session operation reply; Inventory-only readback may carry
    /// them in a fresh signed control answer. A reserved request remains owned
    /// by recovery.
    ///
    /// # Errors
    ///
    /// Returns an error for aliased request digests, corrupt retained response
    /// state, or loss of fixed journal currentness.
    #[doc(hidden)]
    pub fn readback_mount_request(
        &mut self,
        signed_request: aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1,
    ) -> Result<FixedProviderRequestReadbackV1, ProviderLedgerError> {
        use aos_sandbox_source_provider_protocol::{
            SourceProviderMethod, decode_acquire_request, decode_release_request,
            digest_signed_request,
        };

        let signed_request_digest = *digest_signed_request(&signed_request).as_bytes();
        let (method, provider_acquisition_id) = match signed_request.method() {
            SourceProviderMethod::Acquire => (
                SourceProviderMethod::Acquire,
                Some(
                    *decode_acquire_request(signed_request.subject())
                        .map_err(|_| ProviderLedgerError::Equivocation)?
                        .acquisition_id()
                        .as_bytes(),
                ),
            ),
            SourceProviderMethod::Release => (
                SourceProviderMethod::Release,
                Some(
                    *decode_release_request(signed_request.subject())
                        .map_err(|_| ProviderLedgerError::Equivocation)?
                        .acquisition_id()
                        .as_bytes(),
                ),
            ),
            SourceProviderMethod::Inventory => {
                aos_sandbox_source_provider_protocol::decode_inventory_request(
                    signed_request.subject(),
                )
                .map_err(|_| ProviderLedgerError::Equivocation)?;
                (SourceProviderMethod::Inventory, None)
            }
            SourceProviderMethod::Hello => {
                return Err(ProviderLedgerError::InvalidTransition(
                    "Mount request readback cannot select Hello",
                ));
            }
        };
        let canonical_request = signed_request.to_canonical_bytes();
        let readback = self.with_ledger(|ledger| {
            let mut matching_digest = ledger.recovered.attempts.iter().filter(|(_, attempt)| {
                attempt.signed_request_digest.as_bytes() == &signed_request_digest
            });
            let Some((attempt_key, attempt)) = matching_digest.next() else {
                return Ok(FixedProviderRequestReadbackV1::RetryAuthorized(
                    ProtectedProviderMountRetryAuthorityV1 {
                        method,
                        provider_acquisition_id,
                        signed_request_digest,
                    },
                ));
            };
            if matching_digest.next().is_some() || attempt.signed_request != canonical_request {
                return Err(ProviderLedgerError::Equivocation);
            }
            match attempt.state {
                crate::ProviderAttemptStateV1::Reserved => {
                    Ok(FixedProviderRequestReadbackV1::RecoveryPending)
                }
                crate::ProviderAttemptStateV1::Completed => {
                    if attempt.completed_response.is_empty() {
                        return Err(ProviderLedgerError::Corrupt(
                            "completed cold request lacks its response",
                        ));
                    }
                    let attempt_key_bytes = crate::format::attempt_key(attempt_key);
                    let journal_snapshot = ledger.journal.snapshot()?;
                    let persisted = ledger
                        .current_sessions
                        .values_mut()
                        .next()
                        .ok_or(ProviderLedgerError::InvalidTransition(
                            "completed readback has no current Provider session",
                        ))?
                        .session
                        .authorize_persisted_mount_outcome(
                            &ledger.journal,
                            &journal_snapshot,
                            &attempt_key_bytes,
                            &attempt.completed_response,
                        )?;
                    if method == SourceProviderMethod::Acquire {
                        let response =
                            aos_sandbox_source_provider_protocol::decode_acquire_response(
                                &attempt.completed_response,
                            )
                            .map_err(|_| {
                                ProviderLedgerError::Corrupt("completed Acquire response")
                            })?;
                        if response.status()
                            == aos_sandbox_source_provider_protocol::SourceProviderStatus::Complete
                        {
                            let acquisition_id = provider_acquisition_id.ok_or(
                                ProviderLedgerError::Corrupt("completed Acquire identity"),
                            )?;
                            let receipt_acquisition_id = response
                                .signed_receipt()
                                .and_then(|bytes| {
                                    aos_sandbox_source_provider_protocol::SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok()
                                })
                                .map(|receipt| *receipt.subject().acquisition_id().as_bytes())
                                .ok_or(ProviderLedgerError::Corrupt(
                                    "completed Acquire receipt identity",
                                ))?;
                            if receipt_acquisition_id != acquisition_id {
                                return Err(ProviderLedgerError::Equivocation);
                            }
                            return Ok(FixedProviderRequestReadbackV1::AcquireReopen(
                                FixedProviderAcquireReopenV1 {
                                    replay: crate::DurableAcquireReplayV1 {
                                        acquisition_id: aos_sandbox_core::ObjectDigest::from_bytes(
                                            acquisition_id,
                                        ),
                                        attempt_key: attempt_key_bytes,
                                        response: attempt.completed_response.clone(),
                                        journal_snapshot,
                                    },
                                    persisted,
                                },
                            ));
                        }
                    }
                    Ok(FixedProviderRequestReadbackV1::HistoricalOutcome(
                        FixedProviderHistoricalOutcomeV1 {
                            response: attempt.completed_response.clone(),
                            source_root: None,
                            persisted,
                        },
                    ))
                }
                crate::ProviderAttemptStateV1::Retired => Err(
                    ProviderLedgerError::InvalidTransition("cold request attempt is retired"),
                ),
            }
        })?;
        if matches!(readback, FixedProviderRequestReadbackV1::RetryAuthorized(_)) {
            self.priority_mount_retry_digest = Some(signed_request_digest);
            if self.priority_mount_retry_rearm_digest == Some(signed_request_digest) {
                self.priority_mount_retry_rearm_digest = None;
            }
        }
        Ok(readback)
    }

    /// Reads only a completed historical Inventory selected by its signed digest.
    ///
    /// Absent or Reserved attempts yield `None`; this method never constructs a
    /// new-session request or advances Provider's request sequence. The signed
    /// query's Mount record digest is opaque here and must be checked by Mount.
    ///
    /// # Errors
    ///
    /// Rejects digest aliases, a foreign holder/provider, corrupt protected
    /// response, or a retired attempt.
    pub fn readback_inventory_by_digest(
        &mut self,
        query: &InventoryReadbackQueryV1,
    ) -> Result<Option<FixedProviderHistoricalOutcomeV1>, ProviderLedgerError> {
        let signed = self.with_ledger(|ledger| {
            let mut matches =
                ledger.recovered.attempts.values().filter(|attempt| {
                    attempt.signed_request_digest == query.signed_request_digest()
                });
            let Some(attempt) = matches.next() else {
                return Ok(None);
            };
            if matches.next().is_some()
                || attempt.method != SourceProviderMethod::Inventory
                || attempt.provider.authority_id() != query.authorities().0
                || attempt.holder.authority_id() != query.authorities().1
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            match attempt.state {
                crate::ProviderAttemptStateV1::Reserved => Ok(None),
                crate::ProviderAttemptStateV1::Completed => {
                    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(
                        &attempt.signed_request,
                    )
                    .map_err(|_| ProviderLedgerError::Equivocation)?;
                    Ok(Some(signed))
                }
                crate::ProviderAttemptStateV1::Retired => Err(ProviderLedgerError::Equivocation),
            }
        })?;
        let Some(signed) = signed else {
            return Ok(None);
        };
        match self.readback_mount_request(signed)? {
            FixedProviderRequestReadbackV1::HistoricalOutcome(outcome) => Ok(Some(outcome)),
            _ => Err(ProviderLedgerError::Equivocation),
        }
    }

    /// Projects the method and stable provider acquisition owned by recovery.
    ///
    /// The projection grants no request, session, effect, replay, or completion
    /// authority. It exists only so the paired Mount reducer can select and
    /// advance the same durable lineage.
    ///
    /// # Errors
    ///
    /// Returns an error unless protected recovery retains a current work item.
    #[doc(hidden)]
    pub fn backend_recovery_mount_retry_authority(
        &self,
    ) -> Result<ProtectedProviderMountRetryAuthorityV1, ProviderLedgerError> {
        if self.pending_backend_recovery.is_empty() {
            return Err(ProviderLedgerError::InvalidTransition(
                "provider recovery semantic identity is unavailable",
            ));
        }
        let (method, provider_acquisition_id) =
            self.pending_backend_recovery[0].semantic_identity();
        let signed_request_digest = self.pending_backend_recovery[0].signed_request_digest();
        Ok(ProtectedProviderMountRetryAuthorityV1 {
            method,
            provider_acquisition_id,
            signed_request_digest,
        })
    }

    /// Reports whether retained work needs another authenticated successor.
    #[doc(hidden)]
    pub fn backend_recovery_requires_successor_handshake(&self) -> bool {
        !self.pending_backend_recovery.is_empty()
            && !self.pending_backend_recovery[0].has_fresh_request()
            && !self.pending_backend_recovery[0].successor_session_ready()
            && self.recovery_handshake.is_none()
            && self.ingress_reopen.is_none()
    }

    /// Records that the fixed Root-Mount carrier accepted the fresh packet.
    #[doc(hidden)]
    pub fn mark_backend_recovery_request_in_flight(&mut self) -> Result<(), ProviderLedgerError> {
        if self.pending_backend_recovery.is_empty()
            || self.pending_backend_recovery[0].has_fresh_request()
            || !self.pending_backend_recovery[0].successor_session_ready()
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "provider recovery cannot mark another fresh packet in flight",
            ));
        }
        self.pending_backend_recovery[0].mark_fresh_request_in_flight();
        Ok(())
    }

    /// Authenticates and installs the exact retained legacy provider ledger.
    ///
    /// This operation is available only after fixed-owner replay classified
    /// the current namespace as canonical version 2. The live session verifies
    /// the signed provenance manifest, and this owner performs the whole-state
    /// CAS without exposing custody or a raw journal authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for a non-migration state, invalid or
    /// stale provenance, a changed legacy snapshot, failed preflight, or a
    /// definite journal failure. Ambiguous durability is retained in the owner
    /// and reported as [`FixedProviderOwnerStatusV1::MigrationRecoveryRequired`].
    pub fn install_aosspl_v2_to_v3_migration(
        &mut self,
        provenance: crate::SupplementalV2MigrationProvenanceV1,
        canonical_manifest: &[u8],
    ) -> Result<FixedProviderOwnerStatusV1, ProviderLedgerError> {
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let (mut session, canonical_catalog_publication) = match state {
            FixedProviderOwnerStateV1::MigrationRequired {
                session,
                canonical_catalog_publication,
            } => (session, canonical_catalog_publication),
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider ledger does not require migration",
                ));
            }
        };
        let authority = match claim_fixed_provider_authority(self.journal.as_mut()) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRequired {
                    session,
                    canonical_catalog_publication,
                });
                return Err(error.into());
            }
        };
        let authorization: Result<
            aos_sandbox_source_provider_security::AuthorizedV2MigrationPlanV1,
            ProviderLedgerError,
        > = (|| {
            let snapshot = authority.snapshot()?;
            let protected = session.revalidated_provider_configuration()?;
            let catalog = aos_sandbox_source_provider_security::verify_catalog_publication(
                &protected,
                &canonical_catalog_publication,
            )?;
            session
                .authorize_fixed_provider_ledger_migration_v1(
                    &authority,
                    snapshot,
                    catalog,
                    provenance,
                    canonical_manifest,
                )
                .map_err(ProviderLedgerError::from)
        })();
        let authorization = match authorization {
            Ok(authorization) => authorization,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRequired {
                    session,
                    canonical_catalog_publication,
                });
                return Err(error);
            }
        };
        let outcome = ProviderLedgerV1::migrate_aosspl_v2_to_v3_from_fixed_session(
            authority,
            &mut session,
            ProviderLedgerLimits::default(),
            authorization,
        );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRequired {
                    session,
                    canonical_catalog_publication,
                });
                return Err(error);
            }
        };
        match outcome {
            crate::migration::ProtectedAossplMigrationOutcomeV1::Opened(mut ledger) => {
                ledger.install_current_session(session)?;
                self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
                Ok(FixedProviderOwnerStatusV1::Ready)
            }
            crate::migration::ProtectedAossplMigrationOutcomeV1::RecoveryRequired(recovery) => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRecovery {
                    session,
                    canonical_catalog_publication,
                    recovery,
                });
                Ok(FixedProviderOwnerStatusV1::MigrationRecoveryRequired)
            }
        }
    }

    /// Resolves or retries one owner-retained ambiguous migration append.
    ///
    /// The fixed journal is reopened before classification. Exact installed
    /// state is accepted without rewriting; exact legacy state retries the same
    /// authenticated transaction, and every other state fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] unless the owner retains an ambiguous
    /// migration and the reopened fixed journal is exactly old or exactly new.
    pub fn recover_aosspl_v2_to_v3_migration(
        &mut self,
    ) -> Result<FixedProviderOwnerStatusV1, ProviderLedgerError> {
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let (mut session, canonical_catalog_publication, recovery) = match state {
            FixedProviderOwnerStateV1::MigrationRecovery {
                session,
                canonical_catalog_publication,
                recovery,
            } => (session, canonical_catalog_publication, recovery),
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider migration has no ambiguous append",
                ));
            }
        };
        if let Err(error) = self.reopen_fixed_journal() {
            self.state = Some(FixedProviderOwnerStateV1::MigrationRecovery {
                session,
                canonical_catalog_publication,
                recovery,
            });
            return Err(error);
        }
        let authority = match claim_fixed_provider_authority(self.journal.as_mut()) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRecovery {
                    session,
                    canonical_catalog_publication,
                    recovery,
                });
                return Err(error.into());
            }
        };
        let outcome = ProviderLedgerV1::recover_aosspl_v2_to_v3_migration(
            authority,
            &mut session,
            &canonical_catalog_publication,
            ProviderLedgerLimits::default(),
            &recovery,
        );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRecovery {
                    session,
                    canonical_catalog_publication,
                    recovery,
                });
                return Err(error);
            }
        };
        match outcome {
            crate::migration::ProtectedAossplMigrationOutcomeV1::Opened(mut ledger) => {
                ledger.install_current_session(session)?;
                self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
                Ok(FixedProviderOwnerStatusV1::Ready)
            }
            crate::migration::ProtectedAossplMigrationOutcomeV1::RecoveryRequired(recovery) => {
                self.state = Some(FixedProviderOwnerStateV1::MigrationRecovery {
                    session,
                    canonical_catalog_publication,
                    recovery,
                });
                Ok(FixedProviderOwnerStatusV1::MigrationRecoveryRequired)
            }
        }
    }

    /// Sends one durable reply through its exact fixed-owner live session.
    ///
    /// The owner resolves the response's signed session binding internally,
    /// reclaims the same fixed namespace-41 authority used for completion, and
    /// never exposes either the carrier or the raw journal claim.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the owner is not ready, the reply
    /// is malformed, its session is no longer installed, or final durability,
    /// custody, peer, descriptor, or carrier validation fails.
    pub fn send_reply(&mut self, reply: DurableProviderReplyV1) -> Result<(), ProviderLedgerError> {
        let session_binding = reply.session_binding()?;
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state @ (FixedProviderOwnerStateV1::MigrationRequired { .. }
            | FixedProviderOwnerStateV1::MigrationRecovery { .. }) => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider migration is not complete",
                ));
            }
            FixedProviderOwnerStateV1::Handshake {
                security,
                canonical_catalog_publication,
            } => {
                self.state = Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication,
                });
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider handshake is not current",
                ));
            }
        };
        let authority = match claim_fixed_provider_authority(self.journal.as_mut()) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(error.into());
            }
        };
        let mut ledger = ProviderLedgerV1::attach(authority, detached);
        let result = {
            let journal = &ledger.journal;
            let mut matching_sessions = ledger.current_sessions.values_mut().filter(|installed| {
                installed.session.retained_session_binding() == session_binding
            });
            let session = match (matching_sessions.next(), matching_sessions.next()) {
                (Some(session), None) => Ok(session),
                (None, None) => Err(ProviderLedgerError::InvalidTransition(
                    "durable reply session is not installed",
                )),
                _ => Err(ProviderLedgerError::Equivocation),
            };
            match session {
                Ok(session) => reply.send(&mut session.session, journal),
                Err(error) => Err(error),
            }
        };
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
        result
    }

    /// Advances only the authenticated catalog-currentness control exchange.
    ///
    /// The owner retains a nonblocking response with its exact protected
    /// journal snapshot. A newer catalog head invalidates that response rather
    /// than permitting a stale retry. Effect-method packets are rejected by
    /// the current ingress session and never reach backend dispatch.
    ///
    /// # Errors
    ///
    /// Rejects a malformed or replayed query, lowered requested floor,
    /// changed catalog publication or protected head, stale peer, or carrier.
    pub fn advance_catalog_currentness(
        &mut self,
        canonical_catalog_publication: &[u8],
    ) -> Result<FixedProviderCatalogProgressV1, ProviderLedgerError> {
        if canonical_catalog_publication.len() != CANONICAL_CATALOG_PUBLICATION_BYTES {
            return Err(ProviderLedgerError::Corrupt(
                "canonical catalog publication length",
            ));
        }

        if let Some(pending) = self.pending_catalog_currentness.take() {
            let publication_digest =
                ObjectDigest::from_bytes(Sha256::digest(canonical_catalog_publication).into());
            if pending.response.publication_digest() != publication_digest {
                return Err(ProviderLedgerError::ConfigurationMismatch);
            }
            let sent = self.with_ledger(|ledger| {
                let installed = ledger.current_sessions.values_mut().next().ok_or(
                    ProviderLedgerError::InvalidTransition(
                        "fixed provider owner has no live ingress session",
                    ),
                )?;
                installed
                    .session
                    .send_current_catalog_response(
                        &ledger.journal,
                        &pending.current_catalog,
                        &pending.query,
                        &pending.response,
                    )
                    .map_err(Into::into)
            })?;
            if sent {
                return Ok(FixedProviderCatalogProgressV1::Replied);
            }
            self.pending_catalog_currentness = Some(pending);
            return Ok(FixedProviderCatalogProgressV1::Pending);
        }

        let query = self.with_ledger(|ledger| {
            let installed = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition(
                    "fixed provider owner has no live ingress session",
                ),
            )?;
            installed
                .session
                .receive_current_catalog_query()
                .map_err(Into::into)
        })?;
        let Some(query) = query else {
            return Ok(FixedProviderCatalogProgressV1::Pending);
        };
        self.prepare_catalog_currentness_query(canonical_catalog_publication, query)
    }

    /// Advances one catalog query, kernel-coupled Acquire, or holder Inventory.
    ///
    /// The exact source packet is received from live carrier custody and is
    /// branded before leaving this owner. Its signature and durable sequence
    /// are still verified by the reservation reducer. Release and
    /// non-kernel-coupled Acquire remain closed in the production service.
    ///
    /// # Errors
    ///
    /// Rejects malformed frames, source methods other than kernel-coupled
    /// Acquire or Inventory, stale currentness, or changed peer/journal custody.
    pub fn advance_authenticated_ingress(
        &mut self,
        canonical_catalog_publication: &[u8],
    ) -> Result<FixedProviderIngressProgressV1, ProviderLedgerError> {
        if canonical_catalog_publication.len() != CANONICAL_CATALOG_PUBLICATION_BYTES {
            return Err(ProviderLedgerError::Corrupt(
                "canonical catalog publication length",
            ));
        }
        if self.pending_catalog_currentness.is_some() {
            return self
                .advance_catalog_currentness(canonical_catalog_publication)
                .map(|progress| match progress {
                    FixedProviderCatalogProgressV1::Pending => {
                        FixedProviderIngressProgressV1::Pending
                    }
                    FixedProviderCatalogProgressV1::Replied => {
                        FixedProviderIngressProgressV1::CatalogReplied
                    }
                });
        }
        if self.pending_recovery_query_digest.is_some()
            || self.pending_inventory_readback_digest.is_some()
        {
            return Err(ProviderLedgerError::InvalidTransition(
                "recovery answer remains pending on this carrier",
            ));
        }
        let packet = self.with_ledger(|ledger| {
            let installed = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition(
                    "fixed provider owner has no live ingress session",
                ),
            )?;
            installed
                .session
                .receive_current_request_packet()
                .map_err(Into::into)
        })?;
        let Some(packet) = packet else {
            return Ok(FixedProviderIngressProgressV1::Pending);
        };
        if let Ok(query) = CatalogCurrentnessQueryV1::from_canonical_bytes(&packet) {
            return self
                .prepare_catalog_currentness_query(canonical_catalog_publication, query)
                .map(|progress| match progress {
                    FixedProviderCatalogProgressV1::Pending => {
                        FixedProviderIngressProgressV1::Pending
                    }
                    FixedProviderCatalogProgressV1::Replied => {
                        FixedProviderIngressProgressV1::CatalogReplied
                    }
                });
        }
        if packet.starts_with(b"AOSSPC01") {
            return Err(ProviderLedgerError::Equivocation);
        }
        if packet.starts_with(b"AOSSPR01") {
            let query = RecoveryCurrentnessQueryV1::from_canonical_bytes(&packet)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            let binding = self.with_ledger(|ledger| {
                let installed = ledger
                    .current_sessions
                    .values()
                    .next()
                    .ok_or(ProviderLedgerError::Unavailable)?;
                Ok(installed.session.retained_session_binding())
            })?;
            validate_recovery_query_progress(&query, binding, self.last_recovery_sequence)?;
            self.last_recovery_sequence = query.sequence();
            self.pending_recovery_query_digest = Some(query.digest());
            self.pending_recovery_plan_digest = None;
            return Ok(FixedProviderIngressProgressV1::Recovery(query));
        }
        if packet.starts_with(b"AOSSPI01") {
            let query = InventoryReadbackQueryV1::from_canonical_bytes(&packet)
                .map_err(|_| ProviderLedgerError::Equivocation)?;
            let binding = self.with_ledger(|ledger| {
                let installed = ledger
                    .current_sessions
                    .values()
                    .next()
                    .ok_or(ProviderLedgerError::Unavailable)?;
                Ok(installed.session.retained_session_binding())
            })?;
            if query.session_binding() != binding || query.sequence() <= self.last_recovery_sequence
            {
                return Err(ProviderLedgerError::Equivocation);
            }
            self.last_recovery_sequence = query.sequence();
            self.pending_inventory_readback_digest = Some(query.digest());
            return Ok(FixedProviderIngressProgressV1::InventoryReadback(query));
        }
        let signed = SignedSourceProviderRequestV1::from_canonical_bytes(&packet)
            .map_err(|_| ProviderLedgerError::Equivocation)?;
        validate_production_source_request(&signed)?;
        Ok(FixedProviderIngressProgressV1::Source(
            FixedProviderAuthenticatedSourceRequestV1 { signed },
        ))
    }

    /// Sends only an authenticated descriptor-free recovery Unavailable result.
    ///
    /// # Errors
    ///
    /// Rejects a changed new-session binding, signer, peer, or send failure.
    pub fn send_recovery_unavailable(
        &mut self,
        query: &RecoveryCurrentnessQueryV1,
        signed_plan_digest: ObjectDigest,
    ) -> Result<bool, ProviderLedgerError> {
        if self.pending_recovery_query_digest != Some(query.digest())
            || self.last_recovery_sequence != query.sequence()
            || self
                .pending_recovery_plan_digest
                .is_some_and(|digest| digest != signed_plan_digest)
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        self.pending_recovery_plan_digest = Some(signed_plan_digest);
        let sent = self.with_ledger(|ledger| {
            let installed = ledger
                .current_sessions
                .values_mut()
                .next()
                .ok_or(ProviderLedgerError::Unavailable)?;
            let response = installed
                .session
                .sign_recovery_unavailable(query, signed_plan_digest)?;
            installed
                .session
                .send_recovery_unavailable(query, &response)
                .map_err(Into::into)
        })?;
        if sent {
            self.pending_recovery_query_digest = None;
            self.pending_recovery_plan_digest = None;
        }
        Ok(sent)
    }

    /// Sends one signed, descriptor-free protected Inventory readback.
    ///
    /// The historical response is re-read from Provider's completed journal
    /// row for each nonblocking retry. An absent or unresolved row signs only
    /// Unavailable, which cannot complete Mount's Reserved attempt.
    ///
    /// # Errors
    ///
    /// Rejects a changed challenge, foreign descriptor, stale protected
    /// completion, or lost authenticated carrier.
    pub fn send_inventory_readback(
        &mut self,
        query: &InventoryReadbackQueryV1,
        historical: Option<FixedProviderHistoricalOutcomeV1>,
    ) -> Result<bool, ProviderLedgerError> {
        if self.pending_inventory_readback_digest != Some(query.digest())
            || self.last_recovery_sequence != query.sequence()
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        let completed = historical
            .map(|outcome| {
                let (response, source_root, persisted) = outcome.into_security_parts()?;
                if source_root.is_some() {
                    return Err(ProviderLedgerError::Equivocation);
                }
                Ok((response, persisted))
            })
            .transpose()?;
        let sent = self.with_ledger(|ledger| {
            let installed = ledger
                .current_sessions
                .values_mut()
                .next()
                .ok_or(ProviderLedgerError::Unavailable)?;
            let answer = installed
                .session
                .sign_inventory_readback(query, completed)?;
            installed
                .session
                .send_inventory_readback(query, &answer)
                .map_err(Into::into)
        })?;
        if sent {
            self.pending_inventory_readback_digest = None;
        }
        Ok(sent)
    }

    fn prepare_catalog_currentness_query(
        &mut self,
        canonical_catalog_publication: &[u8],
        query: CatalogCurrentnessQueryV1,
    ) -> Result<FixedProviderCatalogProgressV1, ProviderLedgerError> {
        let last_sequence = self.last_catalog_sequence;
        let last_minimum = self.last_catalog_minimum;
        let pending = self.with_ledger(|ledger| {
            let installed = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition(
                    "fixed provider owner has no live ingress session",
                ),
            )?;
            validate_catalog_query_progress(&query, last_sequence, last_minimum)?;

            let snapshot = ledger.journal.snapshot()?;
            let protected = installed.session.revalidated_provider_configuration()?;
            let publication = aos_sandbox_source_provider_security::verify_catalog_publication(
                &protected,
                canonical_catalog_publication,
            )?;
            let current_catalog = installed
                .session
                .authorize_fixed_current_catalog_publication_v1(
                    &ledger.journal,
                    snapshot,
                    publication,
                )?;
            let publication_digest =
                ObjectDigest::from_bytes(Sha256::digest(canonical_catalog_publication).into());
            let response = installed.session.sign_current_catalog_response(
                &ledger.journal,
                &current_catalog,
                &query,
                publication_digest,
            )?;
            Ok(PendingCatalogCurrentnessV1 {
                query,
                response,
                current_catalog,
            })
        })?;

        self.last_catalog_sequence = pending.query.sequence();
        self.last_catalog_minimum = Some(pending.query.minimum());
        self.pending_catalog_currentness = Some(pending);
        self.advance_catalog_currentness(canonical_catalog_publication)
    }

    /// Advances protected provider configuration under its retained live owner.
    ///
    /// The current session and namespace-41 claim are selected internally and
    /// reinstalled before return; neither raw custody nor journal authority is
    /// exposed to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] for a nonready owner, missing live
    /// session, invalid catalog continuity, rollback, equivocation, or commit
    /// and postcommit-currentness failure.
    pub fn advance_protected_configuration(
        &mut self,
        canonical_catalog_publication: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider owner is not ready",
                ));
            }
        };
        let authority = match claim_fixed_provider_authority(self.journal.as_mut()) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(error.into());
            }
        };
        let mut ledger = ProviderLedgerV1::attach(authority, detached);
        let holder_id = ledger.current_sessions.keys().next().copied().ok_or(
            ProviderLedgerError::InvalidTransition(
                "fixed provider owner has no live ingress session",
            ),
        );
        let result = match holder_id {
            Ok(holder_id) => match ledger.current_sessions.remove(&holder_id) {
                Some(mut installed) => {
                    let result = ledger.advance_protected_configuration(
                        &mut installed.session,
                        canonical_catalog_publication,
                    );
                    ledger.current_sessions.insert(holder_id, installed);
                    result
                }
                None => Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider live session disappeared",
                )),
            },
            Err(error) => Err(error),
        };
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
        result
    }

    /// Seals one exact current catalog publication under the fixed provider owner.
    ///
    /// The returned capability contains no journal or signing authority. Its
    /// later consumers must still prove the exact retained snapshot current;
    /// this method merely makes the protected current-head constructor
    /// reachable without exposing custody or a raw namespace-41 claim.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] when the owner is not ready, no live
    /// ingress session exists, or the publication differs from protected
    /// custody or the exact current authority/catalog graph.
    pub fn authorize_current_catalog_publication(
        &mut self,
        canonical_catalog_publication: &[u8],
    ) -> Result<
        aos_sandbox_source_provider_security::ProtectedCurrentCatalogPublicationV1,
        ProviderLedgerError,
    > {
        if canonical_catalog_publication.len() != CANONICAL_CATALOG_PUBLICATION_BYTES {
            return Err(ProviderLedgerError::Corrupt(
                "canonical catalog publication length",
            ));
        }
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider owner is not ready",
                ));
            }
        };
        let authority = match claim_fixed_provider_authority(self.journal.as_mut()) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(error.into());
            }
        };
        let mut ledger = ProviderLedgerV1::attach(authority, detached);
        let result = (|| {
            let snapshot = ledger.journal.snapshot()?;
            let session = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition(
                    "fixed provider owner has no live ingress session",
                ),
            )?;
            let protected = session.session.revalidated_provider_configuration()?;
            let publication = aos_sandbox_source_provider_security::verify_catalog_publication(
                &protected,
                canonical_catalog_publication,
            )?;
            session
                .session
                .authorize_fixed_current_catalog_publication_v1(
                    &ledger.journal,
                    snapshot,
                    publication,
                )
                .map_err(ProviderLedgerError::from)
        })();
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
        result
    }

    /// Runs one operation with the fixed catalog journal claim.
    ///
    /// The higher-ranked closure may combine this claim with a fixed Mount
    /// owner and Root-Mount session, but cannot retain or substitute the raw
    /// namespace-41 authority after the call.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] unless this owner is ready, the fixed
    /// namespace-41 claim remains current, and `operation` succeeds.
    #[doc(hidden)]
    pub fn with_catalog_authority<R>(
        &mut self,
        operation: impl for<'journal> FnOnce(
            &aos_sandbox::ProtectedJournalAuthority<'journal>,
        ) -> Result<R, ProviderLedgerError>,
    ) -> Result<R, ProviderLedgerError> {
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider owner is not ready",
                ));
            }
        };
        let authority = match claim_fixed_provider_authority(self.journal.as_mut()) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(error.into());
            }
        };
        let result = operation(&authority);
        self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
        result
    }

    /// Authenticates and installs one fixed Mount AOSMSA01-to-AOSMSA02 plan.
    ///
    /// The provider owner and Mount-manager owner are borrowed together. The
    /// security session sees only their exact purpose-scoped claims, and the
    /// returned outcome retains the one-shot authorization across ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLedgerError`] unless this provider owner is ready,
    /// both fixed owners are current, and the signed migration inputs match
    /// both complete protected snapshots.
    pub fn install_mount_source_state_migration_v2(
        &mut self,
        mount_owner: &mut aos_sandbox::MountManagerStartupProtectedOwnerV1,
        current_catalog: aos_sandbox_source_provider_security::ProtectedCurrentCatalogPublicationV1,
        supplemental_v2_records: &[(Vec<u8>, Vec<u8>)],
        canonical_manifest: &[u8],
    ) -> Result<
        aos_sandbox_source_provider_security::MountSourceStateMigrationInstallOutcomeV2,
        ProviderLedgerError,
    > {
        let state = self
            .state
            .take()
            .ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state => {
                self.state = Some(state);
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed provider owner is not ready",
                ));
            }
        };
        let provider_authority = match claim_fixed_provider_authority(self.journal.as_mut()) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(error.into());
            }
        };
        let mut mount_authority = match mount_owner.source_migration_authority() {
            Ok(authority) => authority,
            Err(_) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return Err(ProviderLedgerError::InvalidTransition(
                    "fixed Mount migration authority is unavailable",
                ));
            }
        };
        let mut ledger = ProviderLedgerV1::attach(provider_authority, detached);
        let result = (|| {
            let provider_snapshot = ledger.journal.snapshot()?;
            let mount_snapshot = mount_authority.snapshot()?;
            let session = ledger.current_sessions.values_mut().next().ok_or(
                ProviderLedgerError::InvalidTransition(
                    "fixed provider owner has no live ingress session",
                ),
            )?;
            let authorization = session
                .session
                .authorize_fixed_mount_source_state_migration_v2(
                    &ledger.journal,
                    provider_snapshot,
                    &mount_authority,
                    mount_snapshot,
                    current_catalog,
                    supplemental_v2_records,
                    canonical_manifest,
                )?;
            Ok(session
                .session
                .install_fixed_mount_source_state_migration_v2(
                    &ledger.journal,
                    &mut mount_authority,
                    authorization,
                ))
        })();
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
        result
    }

    /// Resolves or retries one retained fixed Mount migration authorization.
    #[must_use]
    pub fn recover_mount_source_state_migration_v2(
        &mut self,
        mount_owner: &mut aos_sandbox::MountManagerStartupProtectedOwnerV1,
        recovery: aos_sandbox_source_provider_security::MountSourceStateMigrationRecoveryV2,
    ) -> FixedMountStateMigrationRecoveryOutcomeV2 {
        let Some(state) = self.state.take() else {
            return FixedMountStateMigrationRecoveryOutcomeV2::RetryRequired {
                error: ProviderLedgerError::RuntimePoisoned,
                recovery,
            };
        };
        let detached = match state {
            FixedProviderOwnerStateV1::Ready(detached) => detached,
            state => {
                self.state = Some(state);
                return FixedMountStateMigrationRecoveryOutcomeV2::RetryRequired {
                    error: ProviderLedgerError::InvalidTransition(
                        "fixed provider owner is not ready",
                    ),
                    recovery,
                };
            }
        };
        let provider_authority = match self
            .journal
            .as_mut()
            .ok_or(ProviderLedgerError::RuntimePoisoned)
            .and_then(|journal| {
                let authority =
                    journal.claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
                authority.validate_fixed_source_provider_storage()?;
                Ok(authority)
            }) {
            Ok(authority) => authority,
            Err(error) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return FixedMountStateMigrationRecoveryOutcomeV2::RetryRequired {
                    error,
                    recovery,
                };
            }
        };
        let mut mount_authority = match mount_owner.source_migration_authority() {
            Ok(authority) => authority,
            Err(_) => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(detached));
                return FixedMountStateMigrationRecoveryOutcomeV2::RetryRequired {
                    error: ProviderLedgerError::InvalidTransition(
                        "fixed Mount migration authority is unavailable",
                    ),
                    recovery,
                };
            }
        };
        let mut ledger = ProviderLedgerV1::attach(provider_authority, detached);
        let outcome = match ledger.current_sessions.values_mut().next() {
            Some(session) => session
                .session
                .recover_fixed_mount_source_state_migration_v2(
                    &ledger.journal,
                    &mut mount_authority,
                    recovery,
                ),
            None => {
                self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
                return FixedMountStateMigrationRecoveryOutcomeV2::RetryRequired {
                    error: ProviderLedgerError::InvalidTransition(
                        "fixed provider owner has no live ingress session",
                    ),
                    recovery,
                };
            }
        };
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
        FixedMountStateMigrationRecoveryOutcomeV2::Resolved(outcome)
    }

    fn reopen_fixed_journal(&mut self) -> Result<(), ProviderLedgerError> {
        drop(self.journal.take());
        let (journal, _) = Journal::open_protected_at(
            Path::new(FIXED_PROVIDER_STATE_ROOT),
            FIXED_PROVIDER_JOURNAL,
            provider_journal_limits(),
        )?;
        self.journal = Some(journal);
        Ok(())
    }
}

fn claim_fixed_provider_authority(
    journal: Option<&mut Journal>,
) -> Result<aos_sandbox::ProtectedJournalAuthority<'_>, ProviderLedgerError> {
    let authority = journal
        .ok_or(ProviderLedgerError::RuntimePoisoned)?
        .claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
    authority.validate_fixed_source_provider_storage()?;
    Ok(authority)
}

fn open_ledger<'journal>(
    journal: &'journal mut Journal,
    session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    canonical_catalog_publication: &[u8],
) -> Result<ProviderLedgerV1<'journal>, ProviderLedgerError> {
    let (authority, configuration) =
        claim_configured_ledger(journal, session, canonical_catalog_publication)?;
    if authority.is_materialized_empty()? {
        ProviderLedgerV1::initialize(authority, configuration)
    } else {
        ProviderLedgerV1::recover(authority, configuration)
    }
}

fn open_claimed_ledger<'journal>(
    authority: aos_sandbox::ProtectedJournalAuthority<'journal>,
    session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    canonical_catalog_publication: &[u8],
) -> Result<ProviderLedgerV1<'journal>, ProviderLedgerError> {
    authority.validate_fixed_source_provider_storage()?;
    let configuration = configured_ledger(session, canonical_catalog_publication)?;
    if authority.is_materialized_empty()? {
        ProviderLedgerV1::initialize(authority, configuration)
    } else {
        ProviderLedgerV1::recover(authority, configuration)
    }
}

fn recover_existing_ledger<'journal>(
    journal: &'journal mut Journal,
    session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    canonical_catalog_publication: &[u8],
) -> Result<Option<ProviderLedgerV1<'journal>>, ProviderLedgerError> {
    let (authority, configuration) =
        claim_configured_ledger(journal, session, canonical_catalog_publication)?;
    if authority.is_materialized_empty()? {
        Ok(None)
    } else {
        ProviderLedgerV1::recover(authority, configuration).map(Some)
    }
}

fn claim_configured_ledger<'journal>(
    journal: &'journal mut Journal,
    session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    canonical_catalog_publication: &[u8],
) -> Result<
    (
        aos_sandbox::ProtectedJournalAuthority<'journal>,
        ProtectedProviderConfigurationV1,
    ),
    ProviderLedgerError,
> {
    let authority = journal.claim_protected_authority(RecordNamespace::SourceProviderAuthority)?;
    authority.validate_fixed_source_provider_storage()?;
    let configuration = configured_ledger(session, canonical_catalog_publication)?;
    Ok((authority, configuration))
}

fn configured_ledger(
    session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
    canonical_catalog_publication: &[u8],
) -> Result<ProtectedProviderConfigurationV1, ProviderLedgerError> {
    let protected = session.revalidated_provider_configuration()?;
    let catalog = aos_sandbox_source_provider_security::verify_catalog_publication(
        &protected,
        canonical_catalog_publication,
    )?;
    ProtectedProviderConfigurationV1::from_revalidated_projections(
        protected,
        catalog,
        ProviderLedgerLimits::default(),
    )
}

fn validate_recovery_query_progress(
    query: &RecoveryCurrentnessQueryV1,
    session_binding: ObjectDigest,
    last_sequence: u64,
) -> Result<(), ProviderLedgerError> {
    if query.session_binding() != session_binding
        || last_sequence.checked_add(1) != Some(query.sequence())
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}

fn validate_catalog_query_progress(
    query: &CatalogCurrentnessQueryV1,
    last_sequence: u64,
    last_minimum: Option<(u64, ObjectDigest)>,
) -> Result<(), ProviderLedgerError> {
    let minimum = query.minimum();
    if query.sequence() <= last_sequence
        || last_minimum.is_some_and(|previous| {
            minimum.0 < previous.0 || (minimum.0 == previous.0 && minimum.1 != previous.1)
        })
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}

const fn provider_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 16 * 1024 * 1024,
        maximum_key_bytes: 1024,
        maximum_records_per_transaction: 4096,
        maximum_transaction_bytes: 64 * 1024 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 512 * 1024 * 1024,
        maximum_materialized_records: 1_000_000,
    }
}

fn validate_production_source_request(
    signed: &SignedSourceProviderRequestV1,
) -> Result<(), ProviderLedgerError> {
    match signed.method() {
        SourceProviderMethod::Acquire => {
            let request = decode_acquire_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Unavailable)?;
            if !request.kernel_coupled() {
                return Err(ProviderLedgerError::Unavailable);
            }
        }
        SourceProviderMethod::Inventory => {
            decode_inventory_request(signed.subject())
                .map_err(|_| ProviderLedgerError::Unavailable)?;
        }
        SourceProviderMethod::Hello | SourceProviderMethod::Release => {
            return Err(ProviderLedgerError::Unavailable);
        }
    }
    Ok(())
}

#[cfg(test)]
mod production_source_ingress_tests {
    use super::*;
    use aos_sandbox_source_provider_protocol::{
        InventorySourceRequestV1, ReleaseSourceRequestV1, SourceProviderKeyUsageV1,
        SourceProviderSigningKeyV1, encode_inventory_request, encode_release_request, sign_request,
    };
    use ed25519_dalek::SigningKey;

    fn signed_request(
        method: SourceProviderMethod,
        subject: Vec<u8>,
    ) -> SignedSourceProviderRequestV1 {
        let key = SigningKey::from_bytes(&[42; 32]);
        let signer = SourceProviderSigningKeyV1::for_signing_key(
            [1; 16],
            1,
            ObjectDigest::from_bytes([2; 32]),
            [3; 16],
            1,
            SourceProviderKeyUsageV1::RootMountRecord,
            &key,
        )
        .unwrap();
        sign_request(method, subject, signer, &key).unwrap()
    }

    #[test]
    fn authenticated_inventory_is_admitted_but_release_remains_closed() {
        let inventory = InventorySourceRequestV1::new(
            ObjectDigest::from_bytes([4; 32]),
            1,
            [5; 16],
            [1; 16],
            1,
            ObjectDigest::from_bytes([2; 32]),
            None,
            100,
        )
        .unwrap();
        let inventory = signed_request(
            SourceProviderMethod::Inventory,
            encode_inventory_request(&inventory),
        );
        assert!(validate_production_source_request(&inventory).is_ok());

        let release = ReleaseSourceRequestV1::new(
            ObjectDigest::from_bytes([4; 32]),
            2,
            [6; 16],
            ObjectDigest::from_bytes([7; 32]),
            [1; 16],
            1,
            ObjectDigest::from_bytes([2; 32]),
            [8; 16],
            ObjectDigest::from_bytes([9; 32]),
            100,
        )
        .unwrap();
        let release = signed_request(
            SourceProviderMethod::Release,
            encode_release_request(&release),
        );
        assert!(matches!(
            validate_production_source_request(&release),
            Err(ProviderLedgerError::Unavailable)
        ));
    }
}

#[cfg(test)]
mod catalog_currentness_tests {
    use super::*;

    fn query(sequence: u64, generation: u64, digest: u8) -> CatalogCurrentnessQueryV1 {
        CatalogCurrentnessQueryV1::new(
            ObjectDigest::from_bytes([1; 32]),
            [2; 32],
            sequence,
            generation,
            ObjectDigest::from_bytes([digest; 32]),
        )
        .unwrap()
    }

    #[test]
    fn catalog_query_sequence_replay_and_floor_downgrade_fail_closed() {
        let previous = Some((4, ObjectDigest::from_bytes([4; 32])));
        assert!(validate_catalog_query_progress(&query(2, 4, 4), 1, previous).is_ok());
        assert!(matches!(
            validate_catalog_query_progress(&query(1, 4, 4), 1, previous),
            Err(ProviderLedgerError::Equivocation)
        ));
        assert!(matches!(
            validate_catalog_query_progress(&query(2, 3, 3), 1, previous),
            Err(ProviderLedgerError::Equivocation)
        ));
        assert!(matches!(
            validate_catalog_query_progress(&query(2, 4, 5), 1, previous),
            Err(ProviderLedgerError::Equivocation)
        ));
    }
}

#[cfg(test)]
mod recovery_currentness_tests {
    use super::*;

    fn query(sequence: u64, session: u8) -> RecoveryCurrentnessQueryV1 {
        RecoveryCurrentnessQueryV1::new(
            ObjectDigest::from_bytes([session; 32]),
            [2; 32],
            sequence,
            [3; 16],
            [4; 16],
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
            ObjectDigest::from_bytes([7; 32]),
        )
        .unwrap()
    }

    #[test]
    fn recovery_query_rejects_replay_gap_old_session_and_overflow() {
        let current = ObjectDigest::from_bytes([1; 32]);
        assert!(validate_recovery_query_progress(&query(1, 1), current, 0).is_ok());
        assert!(validate_recovery_query_progress(&query(2, 1), current, 1).is_ok());
        assert!(validate_recovery_query_progress(&query(1, 1), current, 1).is_err());
        assert!(validate_recovery_query_progress(&query(3, 1), current, 1).is_err());
        assert!(validate_recovery_query_progress(&query(2, 8), current, 1).is_err());
        assert!(validate_recovery_query_progress(&query(u64::MAX, 1), current, u64::MAX).is_err());
    }
}
