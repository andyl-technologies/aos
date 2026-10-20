//! Owns the actual same-Ready Cache current-proof flight and first cause.
//!
//! Root's sealed authenticated invitation precedes each distinct instance. The genuine
//! Root loan admits this concrete layout and the Cache's actual captured BASE,
//! arms all independently owed posts, and remains borrowed through the fresh
//! audit, contacted signer, body comparison and final posts. No raw packet,
//! caller nonce, key, account or boolean constructs a completed proof.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::cache_current_signer_exchange::{
    CacheCurrentSignerExchangeOriginalsV1, CacheCurrentSignerExchangeClosedV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    cache_held::{CacheHeldReceiptDataV1, CACHE_HELD_RECEIPT_BYTES_V1,
        current_proof::{CacheCurrentProofBodyDataV1, CACHE_CURRENT_PROOF_BODY_BYTES_V1,
            CACHE_CURRENT_PROOF_PACKET_BYTES_V1}},
    ready::ReadyBundleDataV1,
    root_open::{RootHelloDataV1, ROOT_HELLO_FRAME_BYTES_V1},
};

use crate::cache_residency::{CacheCurrentAuditOriginalsV1, CacheHeldClosedV1};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::normal_root::CreateStorageRootPeerReceivingOriginalsV1;
use super::root_exchange::{OriginalCreateStorageRootExchangeV1, CreateStorageRootExchangeClosedV1};

/// Distinguishes only the reached Root-owned first-cause destinations.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CacheCurrentProofRootStageV1 { Admission, Before, After }

/// Identifies the actual original payer selected by the sealed Root loan.
///
/// Only its real Initial J or returned U scope supplies this private tag. It
/// cannot replace either original or construct a completed proof owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::controller_resource_reservation::create_intake::ready) enum CacheCurrentProofPurposeV1 {
    InitialJ,
    ReservedU,
}

#[derive(Clone, Copy)]
enum First {
    Purpose,
    Admission,
    RootBefore,
    Audit,
    Inputs,
    Begin,
    Finish,
    Packet,
    Body,
    Association,
    AuditAfter,
    RootAfter,
    Closed,
}

/// Borrows actual challenge bytes and installed IDs from the genuine Root loan.
///
/// The parent constructs this private DATA view only from its accepted original
/// Hello, completed same B/held receipt and measured profile. It grants no IO.
pub(super) struct CacheCurrentSignerInputsV1<'actual> {
    pub(super) hello: &'actual [u8; ROOT_HELLO_FRAME_BYTES_V1],
    pub(super) held: &'actual [u8; CACHE_HELD_RECEIPT_BYTES_V1],
    pub(super) signer_uid: u32,
    pub(super) signer_gid: u32,
    pub(super) socket_gid: u32,
    pub(super) cutoff: u64,
}

/// Retains the actual new Cache current-purpose originals inside the same Ready.
#[derive(Default)]
pub(in crate::controller_resource_reservation::create_intake) struct OriginalCreateStorageCacheCurrentProofV1 {
    entered: bool,
    purpose: Option<Result<CacheCurrentProofPurposeV1, ResourceReservationErrorV1>>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    root_before_entered: bool,
    root_before: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    audits: Option<Box<CacheCurrentAuditOriginalsV1>>,
    audited: Option<Result<(), CacheHeldClosedV1>>,
    transport: CacheCurrentSignerExchangeOriginalsV1,
    signer_entered: bool,
    inputs: Option<Result<(), ResourceReservationErrorV1>>,
    begin: Option<Result<(), CacheCurrentSignerExchangeClosedV1>>,
    finish: Option<Result<(), CacheCurrentSignerExchangeClosedV1>>,
    packet: Option<Result<(), CacheCurrentSignerExchangeClosedV1>>,
    body: Option<Result<CacheCurrentProofBodyDataV1, HistoryErrorV1>>,
    association: Option<Result<(), HistoryErrorV1>>,
    audit_after: Option<Result<(), CacheHeldClosedV1>>,
    root_after_entered: bool,
    root_after: Option<Result<(), CreateStorageRootExchangeClosedV1>>,
    first: Option<First>,
    complete: bool,
    closed: bool,
}

impl OriginalCreateStorageCacheCurrentProofV1 {
    /// Prices this concrete owner, transport and fixed comparison controls.
    ///
    /// The actual captured Cache BASE is supplied separately by the same held
    /// Cache loan. Root's admission retains their complete checked sum plus its
    /// existing cumulative Root BASE before any new native work or allocation.
    pub(super) fn fixed_non_cache_receiving_demand_v1()
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        let unavailable = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let (transport_bytes, files, _transport_cells) =
            CacheCurrentSignerExchangeOriginalsV1::additional_receiving_shape_v1()
                .ok_or_else(unavailable)?;
        let framing = ReadyBundleDataV1::fixed_framing_receiving_demand_v1()
            .ok_or_else(unavailable)?;
        let comparisons = size_of::<CacheCurrentProofBodyDataV1>()
            .checked_add(size_of::<CacheHeldReceiptDataV1<'static>>())
            .and_then(|bytes| bytes.checked_add(size_of::<RootHelloDataV1<'static>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<CacheCurrentSignerInputsV1<'static>>()))
            .ok_or_else(unavailable)?;
        // Each paid flight retains its own audit backing. Its constructor can
        // coexist with that destination; neither belongs to empty intake custody.
        let audit_bytes = size_of::<CacheCurrentAuditOriginalsV1>().checked_mul(2)
            .ok_or_else(unavailable)?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(audit_bytes))
            .and_then(|bytes| bytes.checked_add(transport_bytes))
            .and_then(|bytes| bytes.checked_add(comparisons)).ok_or_else(unavailable)?;
        let comparison_roster = comparison_receiving_demand_v1()?;
        let native = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| unavailable())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| unavailable())?)
            .with(D::NetworkBytes, (8 + ROOT_HELLO_FRAME_BYTES_V1
                + CACHE_HELD_RECEIPT_BYTES_V1 + CACHE_CURRENT_PROOF_PACKET_BYTES_V1) as u64);
        Ok(native.checked_add(framing.with(D::MetadataEntries, 0))?
            .checked_add(comparison_roster)?)
    }

    // Both genuine Root admission paths call this only after their complete
    // fixed and captured-Cache funding succeeds, immediately before arming the
    // independently owed audit. Failed or completed originals remain resident.
    pub(super) fn audit_originals_v1(&mut self) -> &mut CacheCurrentAuditOriginalsV1 {
        self.audits.get_or_insert_with(|| Box::new(CacheCurrentAuditOriginalsV1::default()))
    }

    pub(super) fn purpose_v1(&self)
        -> Result<CacheCurrentProofPurposeV1, ResourceReservationErrorV1>
    {
        self.purpose.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn has_entered_v1(&self) -> bool { self.entered }

    pub(super) fn admission_succeeded_v1(&self) -> bool {
        matches!(self.admission, Some(Ok(())))
    }

    pub(super) fn root_before_entered_v1(&self) -> bool { self.root_before_entered }

    pub(super) fn signer_entered_v1(&self) -> bool { self.signer_entered }

    pub(super) fn root_after_entered_v1(&self) -> bool { self.root_after_entered }

    pub(super) fn audit_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Audit))
    }

    pub(super) fn root_failure_stage_v1(&self) -> Option<CacheCurrentProofRootStageV1> {
        match self.first {
            Some(First::Admission) => Some(CacheCurrentProofRootStageV1::Admission),
            Some(First::RootBefore) => Some(CacheCurrentProofRootStageV1::Before),
            Some(First::RootAfter) => Some(CacheCurrentProofRootStageV1::After),
            _ => None,
        }
    }

    // The Root module's field-split orchestrator alone calls this on the actual
    // Ready resident owner, after the same completed B and invitation checks.
    pub(super) fn produce_once(
        &mut self,
        loan: &mut OriginalCreateStorageRootExchangeV1<'_, '_, '_>,
        peer: &mut CreateStorageRootPeerReceivingOriginalsV1,
        bundle: &[u8],
    ) -> Result<(), CreateStorageRootExchangeClosedV1> {
        if self.entered {
            self.closed = true;
            self.first.get_or_insert(First::Closed);
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.entered = true;
        self.purpose = Some(loan.cache_current_purpose_v1());
        self.mark(!matches!(self.purpose, Some(Ok(_))), First::Purpose);
        if self.first.is_some() { return Err(CreateStorageRootExchangeClosedV1); }

        self.admission = Some(loan.admit_cache_current_once_v1(self));
        self.mark(!matches!(self.admission, Some(Ok(()))), First::Admission);
        if self.first.is_some() { return Err(CreateStorageRootExchangeClosedV1); }

        // Admission armed the exact independently owed Root/Cache/J posts.
        // A failed before pass suppresses primary growth but not those posts.
        self.root_before_entered = true;
        self.root_before = Some(loan.observe_cache_current_before_v1(peer, self));
        self.mark(!matches!(self.root_before, Some(Ok(()))), First::RootBefore);
        if self.first.is_none() {
            self.audited = Some(match self.audits.as_deref_mut() {
                Some(audits) => loan.audit_cache_current_once_v1(audits),
                None => Err(CacheHeldClosedV1),
            });
            self.mark(!matches!(self.audited, Some(Ok(()))), First::Audit);
        }
        if self.first.is_none() {
            match loan.cache_current_signer_inputs_v1(bundle) {
                Ok(actual) => {
                    self.inputs = Some(Ok(()));
                    self.signer_entered = true;
                    self.begin = Some(self.transport.begin_controller_half_once(
                        actual.hello, actual.held, actual.signer_uid, actual.signer_gid,
                        actual.socket_gid, actual.cutoff,
                    ));
                    self.mark(!matches!(self.begin, Some(Ok(()))), First::Begin);
                }
                Err(cause) => {
                    self.inputs = Some(Err(cause));
                    self.first = Some(First::Inputs);
                }
            }
        }
        if self.first.is_none() {
            self.finish = Some(self.transport.finish_once());
            self.mark(!matches!(self.finish, Some(Ok(()))), First::Finish);
        }
        if self.first.is_none() {
            self.packet = Some(self.transport.packet().map(|_| ()));
            self.mark(!matches!(self.packet, Some(Ok(()))), First::Packet);
        }
        if self.first.is_none() {
            self.body = self.transport.packet().ok().map(|packet|
                CacheCurrentProofBodyDataV1::decode(&packet[..CACHE_CURRENT_PROOF_BODY_BYTES_V1]));
            self.mark(!matches!(self.body, Some(Ok(_))), First::Body);
        }
        if self.first.is_none() {
            self.association = Some(match &self.body {
                Some(Ok(body)) => loan.compare_cache_current_body_v1(body, bundle),
                _ => Err(HistoryErrorV1::Malformed),
            });
            self.mark(!matches!(self.association, Some(Ok(()))), First::Association);
        }

        // Entered primary failures cannot erase or suppress these real paid
        // observations. Preserve their whole results after the earlier cause.
        self.audit_after = Some(match self.audits.as_deref_mut() {
            Some(audits) => loan.finish_cache_current_audit_once_v1(audits),
            None => Err(CacheHeldClosedV1),
        });
        self.mark(!matches!(self.audit_after, Some(Ok(()))), First::AuditAfter);
        self.root_after_entered = true;
        self.root_after = Some(loan.observe_cache_current_after_v1(peer, self));
        self.mark(!matches!(self.root_after, Some(Ok(()))), First::RootAfter);
        self.complete = self.first.is_none() && self.audits.as_deref().is_some_and(CacheCurrentAuditOriginalsV1::is_complete);
        if self.complete { Ok(()) } else { Err(CreateStorageRootExchangeClosedV1) }
    }

    fn mark(&mut self, failed: bool, site: First) {
        if failed { self.first.get_or_insert(site); }
    }

    pub(super) fn completed_packet_v1(&self)
        -> Result<&[u8; CACHE_CURRENT_PROOF_PACKET_BYTES_V1], CreateStorageRootExchangeClosedV1>
    {
        if !self.complete || self.first.is_some() || self.closed || !self.audits.as_deref().is_some_and(CacheCurrentAuditOriginalsV1::is_complete)
            || !matches!(self.admission, Some(Ok(())))
            || !matches!(self.root_before, Some(Ok(())))
            || !matches!(self.root_after, Some(Ok(())))
            || !matches!(self.association, Some(Ok(())))
        {
            return Err(CreateStorageRootExchangeClosedV1);
        }
        self.transport.packet().map_err(|_| CreateStorageRootExchangeClosedV1)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)
        -> Option<&(dyn Error + 'static)>
    {
        match self.first? {
            First::Purpose => error(&self.purpose),
            First::Admission => error(&self.admission),
            First::RootBefore => error(&self.root_before),
            First::Audit => self.audits.as_deref().and_then(CacheCurrentAuditOriginalsV1::failure).or_else(|| error(&self.audited)),
            First::Inputs => error(&self.inputs),
            First::Begin => self.transport.failure().or_else(|| error(&self.begin)),
            First::Finish => self.transport.failure().or_else(|| error(&self.finish)),
            First::Packet => self.transport.failure().or_else(|| error(&self.packet)),
            First::Body => error(&self.body),
            First::Association => error(&self.association),
            First::AuditAfter => self.audits.as_deref().and_then(CacheCurrentAuditOriginalsV1::failure).or_else(|| error(&self.audit_after)),
            First::RootAfter => error(&self.root_after),
            First::Closed => Some(&CreateStorageRootExchangeClosedV1),
        }
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

// These new-purpose calls are additional to Ready/B's own framing roster.
// All four argument/local/return/comparison planes are prepaid, even where a
// complete pure call's actual last borrower makes the planes exclusive.
fn comparison_receiving_demand_v1()
    -> Result<ResourceVector, ResourceReservationErrorV1>
{
    use aos_sandbox_model::{RawPairedClockSample, bounded_codec::BoundedReader};
    use aos_sandbox_protocol::domain_ledger::{
        protected_names::ProtectedJournalNamesV1,
        create_storage_history::{
            association::AcceptedAssociationDataV1,
            cache_held::{CacheHeldBodyDataV1, CacheJournalDataV1, CachePhysicalDataV1},
            root_open::RootOpenBodyDataV1,
            transport::OpenQueryV1,
        },
    };

    // Current body decode, Held.body decode and expected post-Held snapshot
    // comparison reach three snapshot carriers. Their nested fixed subcodecs
    // make fifteen journal, three physical and three association calls.
    #[allow(dead_code)]
    struct CurrentComparisonInvocationRosterV1 {
        proof: [CacheCurrentProofBodyDataV1; 4],
        snapshots: [CacheHeldBodyDataV1; 4 * 3],
        journals: [CacheJournalDataV1; 4 * 15],
        physical: [CachePhysicalDataV1; 4 * 3],
        associations: [AcceptedAssociationDataV1; 4 * 3],
        samples: [RawPairedClockSample; 4],
        hellos: [RootHelloDataV1<'static>; 4],
        root_bodies: [RootOpenBodyDataV1; 4],
        opens: [OpenQueryV1; 4],
        receipts: [CacheHeldReceiptDataV1<'static>; 4],
        names: [ProtectedJournalNamesV1; 4 * (15 + 2 + 1)],
        // One proof, three snapshot, fifteen journal, three physical,
        // three association, receipt, Hello, Root body and Open readers.
        readers: [BoundedReader<'static, HistoryErrorV1>; 4 * 29],
        // Every fixed leaf above plus its final enclosing comparison result.
        results: [Result<(), HistoryErrorV1>; 4 * (29 + 1)],
    }

    let bytes = size_of::<CurrentComparisonInvocationRosterV1>();
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes)
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?))
}
