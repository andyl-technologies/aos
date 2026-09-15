//! Fixed-root dormant SourceProvider journal and live-session ownership.
//!
//! The owner is the public construction boundary for provider runtime state.
//! It fixes both protected paths and the namespace, retains the journal lock,
//! drives one caller-supplied connected socket through the sealed security
//! handshake, and lends the resulting ledger only under the same live claim.

use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, RecordNamespace, RecoveryReport};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_source_provider_security::{
    ProviderSourceProviderHandshakeStatusV1, ProviderSourceProviderOwnerV1,
};

use crate::state::{DetachedProviderLedgerV1, ProtectedProviderConfigurationV1};
use crate::{DurableProviderReplyV1, ProviderLedgerError, ProviderLedgerLimits, ProviderLedgerV1};

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

/// Reports exact protected replay performed by the fixed provider owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedProviderOpenReportV1 {
    /// Reports structural replay and any safe partial-tail truncation.
    pub journal: RecoveryReport,
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
/// already-connected descriptor-subject socket, while protected custody and
/// journal locations are compiled in and cannot be redirected.
pub struct FixedProviderOwnerV1 {
    journal: Option<Journal>,
    state: Option<FixedProviderOwnerStateV1>,
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
    /// invalid fixed provider custody, or an invalid connected socket.
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
        let security = ProviderSourceProviderOwnerV1::open_fixed(socket)?;
        Ok((
            Self {
                journal: Some(journal),
                state: Some(FixedProviderOwnerStateV1::Handshake {
                    security,
                    canonical_catalog_publication: canonical_catalog_publication.to_vec(),
                }),
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
        self.state = Some(FixedProviderOwnerStateV1::Ready(ledger.detach()));
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
