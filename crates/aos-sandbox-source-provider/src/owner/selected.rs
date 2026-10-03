//! Selected fixed opening with returned prefixes parked before validation.
//!
//! The selected path shares the ordinary Journal, verifier, configuration and
//! ledger engines. Its first Session occupies the ledger's inline original
//! slot, not the ordinary holder map. Completion therefore lends only the
//! Root1/original-pair route, never generic Ready or recovery authority.

use aos_sandbox_source_provider_security::{
    CurrentProviderIngressSessionV1, SelectedProviderSourceProviderOwnerV1,
    SelectedSourceProviderFailureRefV1,
};

use super::*;

/// Reports the selected original opening without advertising ordinary Ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedSelectedProviderProgressV1 {
    /// The same original HELLO remains pending.
    Pending,
    /// The genuine first Session and recovered runtime remain in this opening.
    OriginalCurrent,
}

/// Lends the same owned first cause without copying or erasing its lower source.
pub enum FixedSelectedProviderFailureRefV1<'owner> {
    /// The opening retains the actual ledger, catalog, verifier or Journal error.
    Ledger(&'owner ProviderLedgerError),
    /// The security prefix retains the actual socket, binding or custody error.
    Security(SelectedSourceProviderFailureRefV1<'owner>),
}

impl core::fmt::Debug for FixedSelectedProviderFailureRefV1<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ledger(_) => formatter.write_str("SelectedProviderFailure([ledger cause])"),
            Self::Security(_) => formatter.write_str("SelectedProviderFailure([security cause])"),
        }
    }
}

/// Retains the selected socket and every genuinely returned opening prefix.
///
/// The existing verifier `Arc` conversion remains an allocation/funding
/// exclusion. No universal allocation-unwind, unreturned lower-open custody,
/// escaped-descriptor drain or cold-session resurrection is claimed.
#[must_use = "retain the selected original and its actual first failure"]
pub struct FixedSelectedProviderOpeningV1 {
    security: Option<SelectedProviderSourceProviderOwnerV1>,
    journal: Option<Journal>,
    raw_verifier: Option<crate::backend_verifier::ProtectedBackendVerifierV1>,
    verifier: Option<Arc<crate::backend_verifier::ProtectedBackendVerifierV1>>,
    hold_challenges: Option<crate::zfs_hold_challenge::ProtectedZfsHoldChallengesV1>,
    session: Option<CurrentProviderIngressSessionV1>,
    runtime: Option<DetachedProviderLedgerV1>,
    publication: Option<Vec<u8>>,
    report: Option<FixedProviderOpenReportV1>,
    completed: Option<FixedProviderOwnerV1>,
    first_failure: Option<ProviderLedgerError>,
    attempted: bool,
    ended: bool,
    moved: bool,
}

impl core::fmt::Debug for FixedSelectedProviderOpeningV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedSelectedProviderOpeningV1([original custody])")
    }
}

struct FixedSelectedOpeningBoundaryV1<'owner> {
    owner: &'owner mut FixedSelectedProviderOpeningV1,
    completed: bool,
}

impl Drop for FixedSelectedOpeningBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end_original();
        }
    }
}

// The same recovered runtime is resident in this scoped destination throughout
// attachment. Refusal shuts down the original queue before returning that
// runtime, including its installed Session, to the outer opening on unwind.
struct SelectedStorageStepV1<'owner, 'journal> {
    security: &'owner mut SelectedProviderSourceProviderOwnerV1,
    return_slot: &'owner mut Option<DetachedProviderLedgerV1>,
    attached: Option<ProviderLedgerV1<'journal>>,
    completed: bool,
}

impl Drop for SelectedStorageStepV1<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.security.end_original();
        }
        if let Some(ledger) = self.attached.take() {
            *self.return_slot = Some(ledger.detach());
        }
    }
}

impl FixedSelectedProviderOpeningV1 {
    fn new(socket: DescriptorSubjectSocket) -> Self {
        Self {
            security: Some(ProviderSourceProviderOwnerV1::begin_fixed_selected_mount_source(socket)),
            journal: None,
            raw_verifier: None,
            verifier: None,
            hold_challenges: None,
            session: None,
            runtime: None,
            publication: None,
            report: None,
            completed: None,
            first_failure: None,
            attempted: false,
            ended: false,
            moved: false,
        }
    }

    /// Opens the selected self role before any protected Journal/verifier read.
    ///
    /// Each returned original is parked before the next lower call. Failure
    /// permanently ends the same original queue; no reopen or retry is offered.
    ///
    /// # Errors
    ///
    /// Lends the actual first returned error and retains all returned prefixes.
    pub fn open_once(&mut self) -> Result<(), FixedSelectedProviderFailureRefV1<'_>> {
        {
            let mut boundary = FixedSelectedOpeningBoundaryV1 { owner: self, completed: false };
            if !boundary.owner.attempted && !boundary.owner.ended && !boundary.owner.moved {
                boundary.owner.attempted = true;
                if let Some(security) = boundary.owner.security.as_mut() {
                    if security.open_once().is_ok() {
                        if let Err(error) = boundary.owner.open_storage() {
                            boundary.owner.first_failure = Some(error);
                        }
                    }
                } else {
                    boundary.owner.first_failure = Some(ProviderLedgerError::RuntimePoisoned);
                }
            } else if boundary.owner.failure().is_none() {
                boundary.owner.first_failure = Some(ProviderLedgerError::InvalidTransition(
                    "selected opening was already attempted",
                ));
            }
            boundary.completed = boundary.owner.failure().is_none()
                && !boundary.owner.ended && !boundary.owner.moved;
        }
        self.finish_step()
    }

    fn open_storage(&mut self) -> Result<(), ProviderLedgerError> {
        let (journal, recovery) = Journal::open_protected_at(
            Path::new(FIXED_PROVIDER_STATE_ROOT),
            FIXED_PROVIDER_JOURNAL,
            provider_journal_limits(),
        )?;
        self.journal = Some(journal);
        self.report = Some(FixedProviderOpenReportV1 { journal: recovery });

        self.raw_verifier = Some(crate::backend_verifier::ProtectedBackendVerifierV1::load_fixed()?);
        // Existing Arc<ProtectedBackendVerifierV1> consumers are unchanged.
        // Originals are resident up to this explicit allocation boundary;
        // allocation failure is not claimed to preserve their Rust ownership.
        if let Some(verifier) = self.raw_verifier.take() {
            self.verifier = Some(Arc::new(verifier));
        } else {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        self.hold_challenges = Some(
            crate::zfs_hold_challenge::ProtectedZfsHoldChallengesV1::open_fixed()?,
        );
        Ok(())
    }

    /// Parks bounded catalog DATA after the selected self role has been opened.
    ///
    /// The caller's fixed protected reader remains responsible for retaining
    /// its own file prefixes. These bytes authorize nothing until the shared
    /// current Session/catalog verifier accepts them under the held Journal.
    ///
    /// # Errors
    ///
    /// Refuses wrong width, repetition, incomplete opening or ended custody.
    pub fn retain_catalog_data(
        &mut self,
        publication: &[u8],
    ) -> Result<(), FixedSelectedProviderFailureRefV1<'_>> {
        {
            let mut boundary = FixedSelectedOpeningBoundaryV1 { owner: self, completed: false };
            if boundary.owner.failure().is_none() {
                if !boundary.owner.attempted || boundary.owner.ended || boundary.owner.moved
                    || boundary.owner.hold_challenges.is_none() || boundary.owner.publication.is_some()
                    || publication.len() != CANONICAL_CATALOG_PUBLICATION_BYTES
                {
                    boundary.owner.first_failure = Some(ProviderLedgerError::Corrupt(
                        "selected canonical catalog publication state or length",
                    ));
                } else {
                    boundary.owner.publication = Some(publication.to_vec());
                }
            }
            boundary.completed = boundary.owner.failure().is_none()
                && !boundary.owner.ended && !boundary.owner.moved;
        }
        self.finish_step()
    }

    /// Advances the existing HELLO and one original first-session installation.
    ///
    /// Ambiguous initialization is retained rather than entering the ordinary
    /// reopen/migration loop. Existing mixed/cold histories cannot be retagged
    /// as a fresh first Session by this opening.
    ///
    /// # Errors
    ///
    /// Ends the original queue and lends its first actual failure, retaining the
    /// Session and returned storage/runtime prefixes through subsequent calls.
    pub fn advance(
        &mut self,
    ) -> Result<FixedSelectedProviderProgressV1, FixedSelectedProviderFailureRefV1<'_>> {
        let mut progress = FixedSelectedProviderProgressV1::Pending;
        {
            let mut boundary = FixedSelectedOpeningBoundaryV1 { owner: self, completed: false };
            if boundary.owner.failure().is_none() && !boundary.owner.ended && !boundary.owner.moved {
                match boundary.owner.advance_inner() {
                    Ok(value) => progress = value,
                    Err(error) => boundary.owner.first_failure = Some(error),
                }
            }
            boundary.completed = boundary.owner.failure().is_none()
                && !boundary.owner.ended && !boundary.owner.moved;
        }
        self.finish_step()?;
        Ok(progress)
    }

    fn advance_inner(&mut self) -> Result<FixedSelectedProviderProgressV1, ProviderLedgerError> {
        if self.completed.is_some() {
            return Ok(FixedSelectedProviderProgressV1::OriginalCurrent);
        }
        if self.publication.is_none() || self.hold_challenges.is_none() {
            return Err(ProviderLedgerError::InvalidTransition(
                "selected storage/catalog opening is incomplete",
            ));
        }
        if self.session.is_none() {
            let security = self.security.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
            match security.advance_handshake() {
                Ok(ProviderSourceProviderHandshakeStatusV1::Pending) => {
                    return Ok(FixedSelectedProviderProgressV1::Pending);
                }
                Ok(ProviderSourceProviderHandshakeStatusV1::Current) => {}
                Err(_) => return Ok(FixedSelectedProviderProgressV1::Pending),
            }
            let authority = claim_fixed_provider_authority(self.journal.as_mut())?;
            let handoff = authority.fixed_source_provider_session_handoff()?;
            match security.take_current_for_fixed_ledger(handoff) {
                Ok(session) => self.session = Some(session),
                Err(_) => return Ok(FixedSelectedProviderProgressV1::Pending),
            }
        }

        if self.runtime.is_none() {
            let journal = self.journal.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
            let session = self.session.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
            let publication = self.publication.as_deref().ok_or(ProviderLedgerError::RuntimePoisoned)?;
            let ledger = open_ledger(journal, session, publication)?;
            self.runtime = Some(ledger.detach());
        }
        self.install_original_session()?;
        self.recheck_original_session()?;
        self.complete_owner()?;
        Ok(FixedSelectedProviderProgressV1::OriginalCurrent)
    }

    fn install_original_session(&mut self) -> Result<(), ProviderLedgerError> {
        // All original Session validation still borrows its resident Option.
        // Detached recovered DATA can be loaned back to the same held Journal.
        let authority = claim_fixed_provider_authority(self.journal.as_mut())?;
        let security = self.security.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        if self.runtime.is_none() {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        let mut boundary = SelectedStorageStepV1 {
            security,
            return_slot: &mut self.runtime,
            attached: None,
            completed: false,
        };
        // All destinations exist before the take. Attach and immediate parking
        // are infallible field moves; the guard now restores the same runtime
        // on every normal or caught-unwind exit without another observation.
        match boundary.return_slot.take() {
            Some(runtime) => boundary.attached = Some(ProviderLedgerV1::attach(authority, runtime)),
            None => return Err(ProviderLedgerError::RuntimePoisoned),
        }
        let result = match boundary.attached.as_mut() {
            Some(ledger) => ledger.install_selected_first_session_retaining(&mut self.session),
            None => Err(ProviderLedgerError::RuntimePoisoned),
        };
        boundary.completed = result.is_ok();
        result
    }

    fn recheck_original_session(&mut self) -> Result<(), ProviderLedgerError> {
        self.verifier.as_ref().ok_or(ProviderLedgerError::RuntimePoisoned)?.revalidate()?;
        let authority = claim_fixed_provider_authority(self.journal.as_mut())?;
        let snapshot = authority.snapshot()?;
        let runtime = self.runtime.as_mut().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        runtime.original_ingress_is_idle()?;
        let (_, _, session) = runtime.original_ingress_parts()?;
        session.current_projection()?;
        authority.validate_source_provider_authority_snapshot(&snapshot)?;
        self.verifier.as_ref().ok_or(ProviderLedgerError::RuntimePoisoned)?.revalidate()?;
        Ok(())
    }

    fn complete_owner(&mut self) -> Result<(), ProviderLedgerError> {
        if self.security.is_none() || self.journal.is_none() || self.verifier.is_none()
            || self.hold_challenges.is_none() || self.runtime.is_none()
            || self.session.is_some() || self.completed.is_some()
            || !self.runtime.as_ref().is_some_and(DetachedProviderLedgerV1::has_selected_first_session)
        {
            return Err(ProviderLedgerError::RuntimePoisoned);
        }
        match (
            self.security.take(), self.journal.take(), self.verifier.take(),
            self.hold_challenges.take(), self.runtime.take(),
        ) {
            (Some(security), Some(journal), Some(verifier), Some(holds), Some(runtime)) => {
                self.completed = Some(FixedProviderOwnerV1 {
                    selected_prefix: Some(security),
                    selected_catalog_packet: None,
                    selected_failure: None,
                    journal: Some(journal),
                    hold_challenges: holds,
                    state: Some(FixedProviderOwnerStateV1::Ready(runtime)),
                    backend_verifier: verifier,
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
                    pending_recovery_terminal_digests: None,
                    pending_inventory_readback_digest: None,
                    original_ingress: original_ingress::OriginalIngressV1::default(),
                    original_runtime: None,
                });
                Ok(())
            }
            (security, journal, verifier, holds, runtime) => {
                self.security = security;
                self.journal = journal;
                self.verifier = verifier;
                self.hold_challenges = holds;
                self.runtime = runtime;
                Err(ProviderLedgerError::RuntimePoisoned)
            }
        }
    }

    /// Moves the completed genuine owner once without a fallible observation.
    ///
    /// The destination remains original-only; it cannot enter ordinary Ready,
    /// generic ledger lending, migration or successor/replacement APIs.
    pub fn take_original_owner(&mut self) -> Option<(FixedProviderOwnerV1, FixedProviderOpenReportV1)> {
        if self.ended || self.moved || self.failure().is_some()
            || self.completed.is_none() || self.report.is_none()
        {
            return None;
        }
        match (self.completed.take(), self.report.take()) {
            (Some(owner), Some(report)) => {
                self.moved = true;
                Some((owner, report))
            }
            (owner, report) => {
                self.completed = owner;
                self.report = report;
                None
            }
        }
    }

    /// Lends the actual first owned error without another observation or retry.
    pub fn failure(&self) -> Option<FixedSelectedProviderFailureRefV1<'_>> {
        self.first_failure.as_ref().map(FixedSelectedProviderFailureRefV1::Ledger)
            .or_else(|| self.security.as_ref().and_then(|security| security.failure())
                .map(FixedSelectedProviderFailureRefV1::Security))
    }

    fn finish_step(&mut self) -> Result<(), FixedSelectedProviderFailureRefV1<'_>> {
        if self.failure().is_none() && !self.ended && !self.moved {
            return Ok(());
        }
        self.end_original();
        if self.failure().is_none() {
            self.first_failure = Some(ProviderLedgerError::RuntimePoisoned);
        }
        match &mut self.first_failure {
            Some(error) => Err(FixedSelectedProviderFailureRefV1::Ledger(error)),
            slot => match self.security.as_ref().and_then(|security| security.failure()) {
                Some(error) => Err(FixedSelectedProviderFailureRefV1::Security(error)),
                None => Err(FixedSelectedProviderFailureRefV1::Ledger(
                    slot.insert(ProviderLedgerError::RuntimePoisoned),
                )),
            },
        }
    }

    /// Ends the same original queue before any returned prefix is destroyed.
    ///
    /// This is irreversible negative closure, not process/descriptor drain.
    pub fn end_original(&mut self) {
        self.ended = true;
        if let Some(security) = self.security.as_mut() {
            security.end_original();
        }
        if let Some(owner) = self.completed.as_mut() {
            owner.end_selected_original();
        }
    }
}

impl Drop for FixedSelectedProviderOpeningV1 {
    fn drop(&mut self) {
        if !self.moved {
            self.end_original();
        }
    }
}

struct SelectedOriginalIngressBoundaryV1<'owner> {
    owner: &'owner mut FixedProviderOwnerV1,
    completed: bool,
}

impl Drop for SelectedOriginalIngressBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end_selected_original();
            if self.owner.selected_failure.is_none() {
                self.owner.selected_failure = Some(ProviderLedgerError::RuntimePoisoned);
            }
        }
    }
}

impl FixedProviderOwnerV1 {
    /// Parks one genuine selected connected original before protected opening.
    ///
    /// This fixed-purpose path supplies no arbitrary role or authority factory.
    pub fn begin_fixed_selected_mount_source(socket: DescriptorSubjectSocket) -> FixedSelectedProviderOpeningV1 {
        FixedSelectedProviderOpeningV1::new(socket)
    }

    fn require_ordinary_owner(&self) -> Result<(), ProviderLedgerError> {
        if self.selected_prefix.is_some() {
            return Err(ProviderLedgerError::InvalidTransition(
                "selected original owner cannot enter generic Ready or recovery",
            ));
        }
        Ok(())
    }

    /// Ends only the same selected original queue without releasing its custody.
    ///
    /// The fixed installed caller uses this negative action for its own retained
    /// deadline, listener or catalog failure. It proves neither drain nor a
    /// terminal Source operation and cannot authorize a replacement carrier.
    pub fn close_selected_original_after_failure(&mut self) {
        self.end_selected_original();
    }

    /// Advances catalog DATA or the same Root1/original-Acquire pairing engine.
    ///
    /// This route never lends a mutable ledger or ordinary admission facade.
    /// Returned unknown/rejected packets and the first owning error remain
    /// resident; no failure permits generic Ready, rotation or replacement.
    ///
    /// # Errors
    ///
    /// Ends the same original queue for changed fixed storage/session/catalog,
    /// malformed control, unexpected ordinary traffic or a lower carrier error.
    pub fn advance_selected_original_ingress(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Result<FixedProviderIngressProgressV1, FixedSelectedProviderFailureRefV1<'_>> {
        if self.selected_prefix.is_none() {
            if self.selected_failure.is_none() {
                self.selected_failure = Some(ProviderLedgerError::InvalidTransition(
                    "selected original custody is absent",
                ));
            }
        } else if self.selected_prefix.as_ref().is_some_and(|prefix| prefix.has_ended()) {
            if self.selected_failure.is_none() {
                self.selected_failure = Some(ProviderLedgerError::RuntimePoisoned);
            }
        } else if self.selected_failure.is_none() {
            let progress = {
                let mut boundary = SelectedOriginalIngressBoundaryV1 {
                    owner: self,
                    completed: false,
                };
                match boundary.owner.advance_selected_original_inner(publication, rows) {
                    Ok(progress) => {
                        boundary.completed = true;
                        Some(progress)
                    }
                    Err(error) => {
                        boundary.owner.selected_failure = Some(error);
                        None
                    }
                }
            };
            if let Some(progress) = progress {
                return Ok(progress);
            }
        }
        self.end_selected_original();
        Err(self.selected_failure_ref())
    }

    fn advance_selected_original_inner(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Result<FixedProviderIngressProgressV1, ProviderLedgerError> {
        if publication.len() != CANONICAL_CATALOG_PUBLICATION_BYTES {
            return Err(ProviderLedgerError::Corrupt("canonical catalog publication length"));
        }
        if self.pending_catalog_currentness.is_some() {
            return self.send_selected_catalog_response(publication);
        }
        match self.receive_original_ingress(publication, Some(rows))? {
            original_ingress::ReceivedOriginalIngressV1::Progress(progress) => Ok(progress),
            original_ingress::ReceivedOriginalIngressV1::Ordinary(packet) => {
                self.selected_catalog_packet = Some(packet);
                let query = CatalogCurrentnessQueryV1::from_canonical_bytes(
                    self.selected_catalog_packet.as_deref().ok_or(ProviderLedgerError::RuntimePoisoned)?,
                ).map_err(|_| ProviderLedgerError::Equivocation)?;

                let authority = claim_fixed_provider_authority(self.journal.as_mut())?;
                let Some(FixedProviderOwnerStateV1::Ready(runtime)) = self.state.as_mut() else {
                    return Err(ProviderLedgerError::RuntimePoisoned);
                };
                runtime.original_ingress_is_idle()?;
                let (_, _, session) = runtime.original_ingress_parts()?;
                let pending = prepare_current_catalog_response(
                    &authority,
                    session,
                    publication,
                    query,
                    self.last_catalog_sequence,
                    self.last_catalog_minimum,
                )?;
                self.last_catalog_sequence = pending.query.sequence();
                self.last_catalog_minimum = Some(pending.query.minimum());
                self.pending_catalog_currentness = Some(pending);
                self.send_selected_catalog_response(publication)
            }
        }
    }

    fn send_selected_catalog_response(
        &mut self,
        publication: &[u8],
    ) -> Result<FixedProviderIngressProgressV1, ProviderLedgerError> {
        let pending = self.pending_catalog_currentness.as_ref().ok_or(ProviderLedgerError::RuntimePoisoned)?;
        let publication_digest = ObjectDigest::from_bytes(Sha256::digest(publication).into());
        if pending.response.publication_digest() != publication_digest {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let authority = claim_fixed_provider_authority(self.journal.as_mut())?;
        let Some(FixedProviderOwnerStateV1::Ready(runtime)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::RuntimePoisoned);
        };
        runtime.original_ingress_is_idle()?;
        let (_, _, session) = runtime.original_ingress_parts()?;
        if !session.send_current_catalog_response(
            &authority, &pending.current_catalog, &pending.query, &pending.response,
        )? {
            return Ok(FixedProviderIngressProgressV1::Pending);
        }
        // Only the exact successfully sent control and its raw DATA complete.
        // The same original Session, prefix, Journal and alias stay resident.
        self.pending_catalog_currentness = None;
        self.selected_catalog_packet = None;
        Ok(FixedProviderIngressProgressV1::CatalogReplied)
    }

    /// Lends negative selected failure custody without observing or retrying.
    pub fn selected_original_failure(&self) -> Option<FixedSelectedProviderFailureRefV1<'_>> {
        let session = match self.state.as_ref() {
            Some(FixedProviderOwnerStateV1::Ready(runtime)) => runtime.selected_original_session(),
            Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) => Some(&held.session),
            _ => self.original_runtime.as_ref().and_then(DetachedProviderLedgerV1::selected_original_session),
        };
        session.and_then(CurrentProviderIngressSessionV1::selected_original_carrier_failure)
            .map(FixedSelectedProviderFailureRefV1::Security)
            .or_else(|| self.selected_failure.as_ref().map(FixedSelectedProviderFailureRefV1::Ledger))
            .or_else(|| self.selected_prefix.as_ref().and_then(|prefix| prefix.failure())
                .map(FixedSelectedProviderFailureRefV1::Security))
    }

    fn selected_failure_ref(&mut self) -> FixedSelectedProviderFailureRefV1<'_> {
        // The current Session's actual socket/binding cause has precedence over
        // its intentionally nonspecific application currentness refusal.
        let session = match self.state.as_ref() {
            Some(FixedProviderOwnerStateV1::Ready(runtime)) => runtime.selected_original_session(),
            Some(FixedProviderOwnerStateV1::HeldReadOnly(held)) => Some(&held.session),
            _ => self.original_runtime.as_ref().and_then(DetachedProviderLedgerV1::selected_original_session),
        };
        if let Some(error) = session.and_then(CurrentProviderIngressSessionV1::selected_original_carrier_failure) {
            return FixedSelectedProviderFailureRefV1::Security(error);
        }
        match &mut self.selected_failure {
            Some(error) => FixedSelectedProviderFailureRefV1::Ledger(error),
            slot => FixedSelectedProviderFailureRefV1::Ledger(slot.insert(ProviderLedgerError::RuntimePoisoned)),
        }
    }

    pub(super) fn end_selected_original(&mut self) {
        if let Some(prefix) = self.selected_prefix.as_mut() {
            prefix.end_original();
        }
    }
}
