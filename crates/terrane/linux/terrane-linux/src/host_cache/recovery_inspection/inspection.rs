//! Composes actual candidate observations while preserving unresolved recovery work.

use super::{
    NativeRecoveryInspector,
    collection::Candidates,
    files::invalid,
    verification::{self, DerivedIndexRepair, DetachedIndexStatus, VerifiedEncodedBody},
};
use crate::publisher_local::{
    Error as PublisherError,
    client::{BodyIncarnationObservation, RecoveryBody},
    wire::{BodyKey, BodyKind, ResultCode},
};
use std::io;
use terrane_sdk::{host::cache::HostDomainLocation, pack::PackId};

/// Identifies unresolved work without claiming rollback, adoption or completion.
#[derive(Debug)]
pub enum RecoveryIssue {
    /// Sealed inspection would adopt or mutate; its genuine witness belongs to the owner.
    SealedWitnessRequired,
    /// An actual pending observation failed; publisher effects may remain uncertain.
    Pending(PublisherError),
    /// An actual canonical inspection failed; no rollback or success is inferred.
    Canonical(PublisherError),
    /// Actual bytes, required dependencies or canonical source custody were unavailable.
    Verification(io::Error),
    /// Only a pending observation survived; no readable canonical source was verified.
    PendingOnly,
}

/// Retains actual observations and optional verified bytes for one registered key.
///
/// Sealed keys remain unresolved. Publisher observations carry their original
/// session and drain scope, and are not serving, pin or reconciliation receipts.
pub struct NativeRecoveryCandidate {
    key: BodyKey,
    pending: Option<BodyIncarnationObservation<HostDomainLocation>>,
    canonical: Option<BodyIncarnationObservation<HostDomainLocation>>,
    verified: Option<VerifiedEncodedBody>,
    issues: Vec<RecoveryIssue>,
}

impl NativeRecoveryCandidate {
    /// Borrows the registered candidate name, which grants no content authority.
    pub fn key(&self) -> &BodyKey {
        &self.key
    }

    /// Borrows independently verified encoded content, when available.
    pub fn verified(&self) -> Option<&VerifiedEncodedBody> {
        self.verified.as_ref()
    }

    /// Borrows unresolved work and physical-effect uncertainty for the owner.
    pub fn issues(&self) -> &[RecoveryIssue] {
        &self.issues
    }

    /// Transfers a derived missing/mismatching-index plan while retaining observations.
    ///
    /// This transfer neither authorizes a write nor completes recovery. A matched
    /// index needs no repair and remains available through [`Self::verified`].
    pub fn take_index_repair(&mut self) -> Option<DerivedIndexRepair> {
        if matches!(&self.verified, Some(VerifiedEncodedBody::Pack(plan)) if plan.detached_index_status() != DetachedIndexStatus::Matches)
        {
            match self.verified.take() {
                Some(VerifiedEncodedBody::Pack(plan)) => Some(*plan),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Borrows the genuine pending pair/name token for native owner reconciliation.
    pub(in crate::host_cache) fn pending_observation(
        &self,
    ) -> Option<&BodyIncarnationObservation<HostDomainLocation>> {
        self.pending.as_ref()
    }
}

/// Reports bounded inspection evidence, never readiness or completed recovery.
///
/// This report performs no local cache/state writes and grants no service or
/// Resume authority. Registered inspections can synchronize names, and
/// InspectPending can durably reconcile retirement leases inside the publisher.
/// Failures retain uncertainty: the physical owner must reconcile those effects
/// and fresh actual quota charges.
pub struct NativeRecoveryInspection {
    context: NativeRecoveryInspector,
    candidates: Vec<NativeRecoveryCandidate>,
    publisher_entries: usize,
    namespace_entries: usize,
    duplicates: usize,
    inventory_failure: Option<PublisherError>,
    namespace_failure: Option<io::Error>,
}

impl NativeRecoveryInspection {
    /// Borrows distinct candidates, including explicitly unresolved sealed keys.
    pub fn candidates(&self) -> &[NativeRecoveryCandidate] {
        &self.candidates
    }

    /// Borrows candidates for transferring derived plans without discarding tokens.
    pub fn candidates_mut(&mut self) -> &mut [NativeRecoveryCandidate] {
        &mut self.candidates
    }

    /// Transfers genuine candidates only when both namespace scans succeeded.
    ///
    /// The owner must preflight every candidate issue and check actual context
    /// before extraction, then retain its final exhaustive second report.
    /// Extraction performs no currentness check, clears no candidate issue and
    /// grants no lifecycle, completed-recovery or serving authority.
    ///
    /// # Errors
    /// Returns the entire original report, including context, resources and
    /// typed failures, if publisher inventory or shared namespace scanning failed.
    pub(in crate::host_cache) fn try_into_candidates(
        self,
    ) -> Result<Vec<NativeRecoveryCandidate>, Box<Self>> {
        if self.inventory_failure.is_some() || self.namespace_failure.is_some() {
            return Err(Box::new(self));
        }
        Ok(self.candidates)
    }

    /// Returns publisher key occurrences counted before deduplication.
    pub fn publisher_entries(&self) -> usize {
        self.publisher_entries
    }

    /// Returns actual shared namespace entries counted, including parent shards.
    pub fn namespace_entries(&self) -> usize {
        self.namespace_entries
    }

    /// Returns repeated keys counted across all collected sources.
    pub fn duplicate_entries(&self) -> usize {
        self.duplicates
    }

    /// Borrows a failed inventory exchange; absence alone is not recovery completion.
    pub fn inventory_failure(&self) -> Option<&PublisherError> {
        self.inventory_failure.as_ref()
    }

    /// Borrows a failed shared scan; a partial inventory cannot authorize completion.
    pub fn namespace_failure(&self) -> Option<&io::Error> {
        self.namespace_failure.as_ref()
    }

    /// Rechecks the actual retained process and domain roots without owner effects.
    ///
    /// # Errors
    /// Refuses changed process confinement or root incarnations.
    pub fn check_current(&self) -> io::Result<()> {
        self.context.check_current()
    }
}

impl NativeRecoveryInspector {
    /// Derives bounded missing-index work without asking publisher inventory.
    ///
    /// A sealed manifest's descriptor may itself require its cached index.
    /// These independently verified shared packs supply repair data only; they
    /// establish neither private namespace completeness nor pending absence.
    /// The physical owner must check both before adoption or serving.
    ///
    /// # Errors
    /// Refuses unknown names, invalid packs or dependencies, mismatching indexes,
    /// stale native custody and aggregate retained-index allocation overflow.
    pub(in crate::host_cache) fn inspect_index_repairs(
        &self,
    ) -> io::Result<Vec<DerivedIndexRepair>> {
        self.check_current()?;
        let mut collected = Candidates::new(self.max_candidates);
        collected.shared_packs(self)?;
        let packs = collected
            .keys()
            .map(pack_id)
            .collect::<io::Result<Vec<_>>>()?;
        let mut repairs = Vec::new();
        let mut retained = 0_usize;
        for id in &packs {
            let VerifiedEncodedBody::Pack(plan) = verification::pack(self, *id, None, &packs)?
            else {
                return Err(invalid(
                    "shared pack verification returned another body kind",
                ));
            };
            match plan.detached_index_status() {
                DetachedIndexStatus::Matches => {}
                DetachedIndexStatus::Mismatch => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "recovery will not overwrite a mismatching detached index",
                    ));
                }
                DetachedIndexStatus::Missing => {
                    retained = retained
                        .checked_add(plan.index_bytes().len())
                        .filter(|bytes| *bytes <= self.reads.max_allocation_bytes)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::OutOfMemory,
                                "startup repair indexes exceed aggregate retained read budget",
                            )
                        })?;
                    repairs.try_reserve(1).map_err(io::Error::other)?;
                    repairs.push(*plan);
                }
            }
        }
        self.check_current()?;
        Ok(repairs)
    }

    /// Inspects bounded actual names and bytes without local cache/state mutations.
    ///
    /// Inventory and unsealed InspectBody preserve registered publisher custody.
    /// Those inspections may synchronize names, and InspectPending may reconcile
    /// retirement leases in that owner. Any failed exchange remains unresolved
    /// physical-effect uncertainty. Sealed
    /// InspectBody and Adopt are deliberately never issued. Missing detached
    /// indexes are derived only from fully verified actual canonical pack bytes.
    ///
    /// # Errors
    /// Refuses stale native context or exhausted namespace occurrence budgets,
    /// or malformed/nonprogressing inventory. Candidate verification failures and
    /// unavailable inventory retain explicit unresolved report outcomes.
    pub fn inspect(&self) -> io::Result<NativeRecoveryInspection> {
        self.check_current()?;
        let mut collected = Candidates::new(self.max_candidates);
        collected.publisher(self)?;
        if let Err(error) = collected.shared_packs(self) {
            if error.kind() == io::ErrorKind::OutOfMemory {
                return Err(error);
            }
            collected.namespace_failure = Some(error);
        }
        let packs = collected
            .keys()
            .filter(|key| key.kind == BodyKind::Pack as i32)
            .map(pack_id)
            .collect::<io::Result<Vec<_>>>()?;
        let mut candidates = Vec::new();
        let mut retained_index_bytes = 0_usize;
        // An uncertain inventory exchange does not establish a usable publisher
        // command scope. Shared bytes can still yield derived source evidence.
        let publisher_available = collected.inventory_failure.is_none();
        for key in collected.keys() {
            self.check_current()?;
            let mut candidate = self.inspect_candidate(key, &packs, publisher_available);
            if let Some(VerifiedEncodedBody::Pack(plan)) = candidate.verified() {
                match retained_index_bytes.checked_add(plan.index_bytes().len()) {
                    Some(next) if next <= self.reads.max_allocation_bytes => {
                        retained_index_bytes = next
                    }
                    _ => {
                        // Preserve genuine lifecycle tokens even when the next
                        // derived allocation cannot remain in this bounded report.
                        candidate.verified = None;
                        candidate
                            .issues
                            .push(RecoveryIssue::Verification(io::Error::new(
                                io::ErrorKind::OutOfMemory,
                                "derived indexes exceed aggregate retained read budget",
                            )));
                    }
                }
            }
            candidates.push(candidate);
        }
        self.check_current()?;
        Ok(NativeRecoveryInspection {
            context: self.clone(),
            candidates,
            publisher_entries: collected.publisher_entries,
            namespace_entries: collected.namespace_entries,
            duplicates: collected.duplicates,
            inventory_failure: collected.inventory_failure,
            namespace_failure: collected.namespace_failure,
        })
    }

    fn inspect_candidate(
        &self,
        key: &BodyKey,
        packs: &[PackId],
        publisher_available: bool,
    ) -> NativeRecoveryCandidate {
        let mut candidate = NativeRecoveryCandidate {
            key: key.clone(),
            pending: None,
            canonical: None,
            verified: None,
            issues: Vec::new(),
        };
        if publisher_available {
            match self.session.inspect_pending(key.clone()) {
                Ok(observation) => candidate.pending = Some(observation),
                Err(PublisherError::Remote(ResultCode::NotFound)) => {}
                Err(error) => candidate.issues.push(RecoveryIssue::Pending(error)),
            }
        }
        if key.kind == BodyKind::Sealed as i32 {
            candidate.issues.push(RecoveryIssue::SealedWitnessRequired);
            return candidate;
        }
        let body = if publisher_available {
            match self.session.inspect_body(key.clone(), None) {
                Ok(RecoveryBody::Encoded { body, observation }) => {
                    candidate.canonical = Some(observation);
                    Some(body)
                }
                Ok(RecoveryBody::Sealed { .. }) => {
                    candidate.issues.push(RecoveryIssue::Verification(invalid(
                        "unsealed inspection returned sealed custody",
                    )));
                    None
                }
                Err(error) => {
                    candidate.issues.push(RecoveryIssue::Canonical(error));
                    None
                }
            }
        } else {
            None
        };
        let verified = match BodyKind::try_from(key.kind) {
            Ok(BodyKind::Pack) => pack_id(key).and_then(|id| {
                verification::pack(self, id, body.as_ref().map(|body| body.handle()), packs)
            }),
            Ok(BodyKind::Chunk) => match &body {
                Some(body) => verification::chunk(self, key, body.handle(), packs),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "canonical chunk candidate has no actual publisher descriptor",
                )),
            },
            _ => Err(invalid("unexpected recovery candidate kind")),
        };
        match verified {
            Ok(verified) => candidate.verified = Some(verified),
            Err(error) => candidate.issues.push(RecoveryIssue::Verification(error)),
        }
        if candidate.pending.is_some() && candidate.verified.is_none() {
            candidate.issues.push(RecoveryIssue::PendingOnly);
        }
        candidate
    }
}

fn pack_id(key: &BodyKey) -> io::Result<PackId> {
    let bytes = key.pack_id.as_slice().try_into().map_err(invalid)?;
    Ok(PackId::from_random_bytes(bytes))
}
