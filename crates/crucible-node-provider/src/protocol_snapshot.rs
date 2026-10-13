//! Source-private protocol byte snapshots without native installation authority.
//!
//! Reservations precede child construction. Capturing borrows complete actual
//! state twice under one exclusive actor: a no-allocation count, then a bounded
//! write into the same precharged buffer. Decoding never produces an installed
//! capture, process lease, semantic seal or fresh-adoption permission.

use crate::{ProviderError, handshake::ConnectionAuthority};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::io::{self, Write};
use std::rc::Rc;

/// Selects the actual correlation cut retained by a source-private capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolCaptureCut {
    /// Requires no outstanding transport correlations after the full prefix.
    HostSettled,
    /// Retains exactly the current incoming Capture before its response.
    NativeIncomingCapture,
}

/// Reports retained allocation facts from one current installed native-five bank.
///
/// Numeric facts grant no source selection, capture, release or adoption right.
/// The source factory must join actual native owners and its original budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct OriginalProtocolStorageFacts {
    /// States the genuinely negotiated maximum encoded frame body length.
    pub maximum_frame_bytes: usize,
    /// Bounds shared literal bytes across both lifetime directions.
    pub maximum_history_bytes: usize,
    /// Bounds each direction's nonrenewing lifetime frame population.
    pub maximum_frames_per_direction: usize,
    /// Reports actual allocated byte capacity rather than logical usage.
    pub byte_capacity: usize,
    /// Reports actual allocated descriptor population across both directions.
    pub descriptor_capacity: usize,
    /// Reports actual descriptor allocation in bytes.
    pub descriptor_bytes: usize,
    /// Reports complete charged byte and descriptor allocation.
    pub allocated_bytes: usize,
    /// Counts literal bytes retained under the same original bank.
    pub retained_bytes: usize,
    /// Counts original incoming lifetime slots, including incomplete ones.
    pub incoming_frames: usize,
    /// Counts original outgoing lifetime slots, including incomplete ones.
    pub outgoing_frames: usize,
    /// Reports complete physical I/O for all retained slots, not semantic success.
    pub all_io_complete: bool,
}

pub(crate) struct ProtocolCaptureOwner {
    pid: u32,
    thread: std::thread::ThreadId,
}

impl ProtocolCaptureOwner {
    pub(crate) fn new() -> Self {
        Self {
            pid: std::process::id(),
            thread: std::thread::current().id(),
        }
    }
    pub(crate) fn ensure_current(&self) -> Result<(), ProviderError> {
        if self.pid != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "protocol capture owner changed process or thread",
            ));
        }
        Ok(())
    }
}

/// Owns finite snapshot byte capacity charged before child construction.
pub struct ProtocolSnapshotReservation {
    bytes: Vec<u8>,
    maximum: usize,
    complete: bool,
    literal: Option<crate::transport::original_frames::OriginalFrameReservation>,
    issuer: Option<(
        ConnectionAuthority,
        Rc<ProtocolCaptureOwner>,
        ProtocolCaptureCut,
        crate::operational_time::OperationalDeadline,
    )>,
}

impl ProtocolSnapshotReservation {
    /// Allocates a positive bounded snapshot buffer before native effects.
    ///
    /// # Errors
    /// Refuses zero, more than 512 MiB, or allocator failure.
    pub fn reserve(maximum: usize) -> Result<Self, ProviderError> {
        if maximum == 0 || maximum > crate::transport::original_frames::MAX_ORIGINAL_FRAME_BYTES {
            return Err(ProviderError::ResourceExhausted(
                "protocol snapshot reservation",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum)
            .map_err(|_| ProviderError::ResourceExhausted("protocol snapshot bytes"))?;
        Ok(Self {
            bytes,
            maximum,
            complete: false,
            literal: None,
            issuer: None,
        })
    }

    /// Reserves the encoded snapshot and an independent complete literal copy.
    ///
    /// Both byte and descriptor banks precede child construction. The selected
    /// source profile must charge these copies in addition to both endpoint
    /// archives, prefix ownership and temporary decoding/metadata storage.
    ///
    /// # Errors
    /// Refuses invalid limits or allocator failure without native effects.
    pub fn reserve_complete(
        maximum: usize,
        history_bytes: usize,
        lifetime_frames: usize,
    ) -> Result<Self, ProviderError> {
        let mut original = Self::reserve(maximum)?;
        original.literal = Some(
            crate::transport::original_frames::OriginalFrameReservation::reserve(
                history_bytes,
                lifetime_frames,
            )?,
        );
        Ok(original)
    }

    pub(crate) fn validate_literal_reservation(
        &self,
        original: &crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        let target = self.literal.as_ref().ok_or(ProviderError::Correlation(
            "complete snapshot requires precharged original literal copy",
        ))?;
        original.validate_empty_copy(target)
    }

    pub(crate) fn retain_literal_history(
        &mut self,
        original: &crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        let target = self.literal.as_mut().ok_or(ProviderError::Correlation(
            "complete snapshot requires precharged original literal copy",
        ))?;
        if let Err(error) = original.copy_into_empty(target) {
            self.complete = false;
            return Err(error);
        }
        Ok(())
    }

    /// Reports the actual snapshot allocation to its source-owned budget.
    pub fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
            + self
                .literal
                .as_ref()
                .map_or(0, |literal| literal.allocated_bytes())
    }

    pub(crate) fn encode(&mut self, state: &impl Serialize) -> Result<(), ProviderError> {
        if !self.bytes.is_empty() {
            return Err(ProviderError::Conflict(
                "protocol snapshot reservation already used",
            ));
        }
        struct Count {
            used: usize,
            maximum: usize,
        }
        impl Write for Count {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.used = self
                    .used
                    .checked_add(bytes.len())
                    .filter(|n| *n <= self.maximum)
                    .ok_or_else(|| io::Error::other("protocol snapshot complete credit"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut count = Count {
            used: 0,
            maximum: self.maximum,
        };
        serde_json::to_writer(&mut count, state)
            .map_err(|_| ProviderError::ResourceExhausted("complete borrowed protocol snapshot"))?;
        struct Bounded<'a> {
            bytes: &'a mut Vec<u8>,
            maximum: usize,
        }
        impl Write for Bounded<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.len() > self.maximum - self.bytes.len() {
                    return Err(io::Error::other("protocol snapshot writer limit"));
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Bounded {
            bytes: &mut self.bytes,
            maximum: count.used,
        };
        serde_json::to_writer(&mut writer, state)
            .map_err(|_| ProviderError::Frame("protocol snapshot bounded encoding"))?;
        if self.bytes.len() != count.used {
            return Err(ProviderError::Conflict(
                "protocol snapshot state changed during capture",
            ));
        }
        self.complete = true;
        Ok(())
    }

    pub(crate) fn bind(
        &mut self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        cut: ProtocolCaptureCut,
        deadline: crate::operational_time::OperationalDeadline,
    ) -> Result<(), ProviderError> {
        owner.ensure_current()?;
        if self.issuer.is_some() {
            return Err(ProviderError::Conflict(
                "protocol snapshot attempt already bound",
            ));
        }
        self.issuer = Some((authority.clone(), owner.clone(), cut, deadline));
        Ok(())
    }

    pub(crate) fn validate_issuer(
        &self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        cut: ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        owner.ensure_current()?;
        let Some((original, issuer, original_cut, _)) = &self.issuer else {
            return Err(ProviderError::Correlation(
                "protocol snapshot has no original issuer",
            ));
        };
        if !self.complete
            || self.bytes.is_empty()
            || !original.same_registration(authority)
            || !Rc::ptr_eq(issuer, owner)
            || *original_cut != cut
        {
            return Err(ProviderError::Correlation(
                "protocol snapshot changed original issuer or cut",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish(
        self,
        authority: &ConnectionAuthority,
        owner: &Rc<ProtocolCaptureOwner>,
        cut: ProtocolCaptureCut,
    ) -> Result<OriginalProtocolSnapshot, ProviderError> {
        self.validate_issuer(authority, owner, cut)?;
        let (original, issuer, original_cut, deadline) = self.issuer.ok_or(
            ProviderError::Correlation("protocol snapshot has no original issuer"),
        )?;
        if !self.complete
            || self.bytes.is_empty()
            || !original.same_registration(authority)
            || !Rc::ptr_eq(&issuer, owner)
            || original_cut != cut
        {
            return Err(ProviderError::Correlation(
                "protocol snapshot changed original issuer or cut",
            ));
        }
        Ok(OriginalProtocolSnapshot {
            bytes: self.bytes,
            authority: original,
            owner: issuer,
            cut,
            deadline,
            literal: self.literal,
        })
    }
}

/// Retains bytes issued by the actual controller and its original authority.
///
/// Private construction distinguishes this owner result from arbitrary decoded
/// data. It grants no native adoption or readiness; the source must authenticate
/// its complete semantic and process custody and literal Hello originals.
pub struct OriginalProtocolSnapshot {
    bytes: Vec<u8>,
    authority: ConnectionAuthority,
    owner: Rc<ProtocolCaptureOwner>,
    cut: ProtocolCaptureCut,
    deadline: crate::operational_time::OperationalDeadline,
    literal: Option<crate::transport::original_frames::OriginalFrameReservation>,
}

impl OriginalProtocolSnapshot {
    /// Borrows exact source-private snapshot bytes without reencoding frames.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Borrows the independently frozen original literal frames when reserved.
    pub fn literal_frames(
        &self,
    ) -> Option<impl Iterator<Item = crate::transport::original_frames::OriginalFrame<'_>>> {
        self.literal.as_ref().map(|literal| literal.frames())
    }

    /// Copies frozen historical frames into an empty precharged data bank.
    ///
    /// This preserves raw old-scope bytes, directional counts, lifetime IDs and
    /// exact original byte/descriptor capacities. It does not install a stream,
    /// rebind any envelope, replay a request or grant native adoption/readiness.
    /// The source factory must separately install complete decoded state after
    /// genuine fresh Hello and its private semantic/native settlement proof.
    ///
    /// # Errors
    /// Refuses a copied process/thread owner, absent precharged original copy,
    /// pending native Capture, a used target or differing complete allocation.
    /// Refusal leaves both original snapshot and target history unchanged.
    pub fn prepare_historical_frame_data(
        &self,
        target: &mut crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        self.owner.ensure_current()?;
        if self.cut != ProtocolCaptureCut::HostSettled {
            return Err(ProviderError::Correlation(
                "pending native Capture requires source-owned settlement",
            ));
        }
        let literal = self.literal.as_ref().ok_or(ProviderError::Correlation(
            "original snapshot literal copy was not reserved",
        ))?;
        literal.copy_into_empty(target)
    }

    /// Reports the authenticated correlation cut used by the original capture.
    pub fn cut(&self) -> ProtocolCaptureCut {
        self.cut
    }
    /// Reports exhaustion of the retained original physical cut without renewing it.
    pub fn original_physical_cut_expired(&self) -> bool {
        self.deadline.is_expired()
    }
    pub(crate) fn same_owner(
        &self,
        owner: &Rc<ProtocolCaptureOwner>,
        authority: &ConnectionAuthority,
    ) -> bool {
        owner.ensure_current().is_ok()
            && self.owner.ensure_current().is_ok()
            && Rc::ptr_eq(&self.owner, owner)
            && self.authority.same_registration(authority)
    }
}

/// Retains actual old and fresh registrations for source-owned adoption checks.
///
/// Preparation validates two opaque original actors and genuine live fresh
/// Hello registration at a settled host cut. Pending native Capture remains closed
/// until the source factory supplies its private verified settlement.
/// It installs no history, counter, native state or Ready
/// permission. Source5 must join its complete verified settlement and models.
pub struct PreparedFreshProtocolMapping {
    original: ConnectionAuthority,
    original_owner: Rc<ProtocolCaptureOwner>,
    fresh: ConnectionAuthority,
    fresh_owner: Rc<ProtocolCaptureOwner>,
    cut: ProtocolCaptureCut,
}

impl PreparedFreshProtocolMapping {
    pub(crate) fn prepare(
        original: &OriginalProtocolSnapshot,
        fresh: &ConnectionAuthority,
        fresh_owner: &Rc<ProtocolCaptureOwner>,
    ) -> Result<Self, ProviderError> {
        original.owner.ensure_current()?;
        fresh_owner.ensure_current()?;
        fresh.ensure_live()?;
        if original.authority.same_registration(fresh)
            || original.authority.connection_id() == fresh.connection_id()
            || original.authority.session_id() == fresh.session_id()
            || original.authority.incarnation_id() == fresh.incarnation_id()
            || original.literal.is_none()
            || original.cut != ProtocolCaptureCut::HostSettled
        {
            return Err(ProviderError::Correlation(
                "fresh protocol mapping requires new scope and settled frozen original history",
            ));
        }
        Ok(Self {
            original: original.authority.clone(),
            original_owner: original.owner.clone(),
            fresh: fresh.clone(),
            fresh_owner: fresh_owner.clone(),
            cut: original.cut,
        })
    }

    /// Rechecks the same retained actual actors and fresh registration.
    ///
    /// # Errors
    /// Refuses process/thread drift, revoked fresh Hello or substituted original
    /// snapshot. This check supplies no semantic settlement or native permission.
    pub fn validate_original(
        &self,
        original: &OriginalProtocolSnapshot,
    ) -> Result<(), ProviderError> {
        self.original_owner.ensure_current()?;
        self.fresh_owner.ensure_current()?;
        self.fresh.ensure_live()?;
        if !self.original.same_registration(&original.authority)
            || !Rc::ptr_eq(&self.original_owner, &original.owner)
            || self.cut != original.cut
        {
            return Err(ProviderError::Correlation(
                "fresh mapping original owner changed",
            ));
        }
        Ok(())
    }
}

pub(crate) struct Sequence<F>(pub(crate) F);
impl<F, I> Serialize for Sequence<F>
where
    F: Fn() -> I,
    I: Iterator,
    I::Item: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for item in (self.0)() {
            sequence.serialize_element(&item)?;
        }
        sequence.end()
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These snapshot controls deliberately panic on invalid fixtures.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native5_original_pending_capture_mapping_requires_source_owned_settlement() {
        let (_old_handshake, old) = crate::handshake::tests::authority();
        let (_fresh_handshake, fresh) =
            crate::handshake::tests::authority_with_scope("pending-target");
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let fresh_owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve_complete(1024, 1024, 2).unwrap();
        reserve
            .bind(
                &old,
                &owner,
                ProtocolCaptureCut::NativeIncomingCapture,
                deadline,
            )
            .unwrap();
        reserve
            .encode(&json!({"incoming":"original Capture"}))
            .unwrap();
        let snapshot = reserve
            .finish(&old, &owner, ProtocolCaptureCut::NativeIncomingCapture)
            .unwrap();

        assert!(PreparedFreshProtocolMapping::prepare(&snapshot, &fresh, &fresh_owner).is_err());
        let mut history =
            crate::transport::original_frames::OriginalFrameReservation::reserve(1024, 2).unwrap();
        assert!(
            snapshot
                .prepare_historical_frame_data(&mut history)
                .is_err()
        );
        assert_eq!(history.frames().count(), 0);
        assert!(fresh.ensure_live().is_ok());
        assert!(!snapshot.bytes().is_empty());
    }

    #[test]
    fn native5_original_snapshot_foreign_process_owner_refuses_before_issuer_or_copy() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let mut owner = ProtocolCaptureOwner::new();
        owner.pid = owner.pid.wrapping_add(1);
        let owner = Rc::new(owner);
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve(1024).unwrap();
        assert!(
            reserve
                .bind(
                    &authority,
                    &owner,
                    ProtocolCaptureCut::HostSettled,
                    deadline
                )
                .is_err()
        );
        assert!(reserve.issuer.is_none());
        assert!(reserve.bytes.is_empty());
    }

    #[test]
    fn native5_original_snapshot_credit_precedes_copy_and_failed_attempt_stays_bound() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve(2).unwrap();
        reserve
            .bind(
                &authority,
                &owner,
                ProtocolCaptureCut::HostSettled,
                deadline,
            )
            .unwrap();
        assert!(reserve.encode(&json!({"large": [1,2,3]})).is_err());
        assert!(reserve.bytes.is_empty());
        assert!(
            reserve
                .bind(
                    &authority,
                    &owner,
                    ProtocolCaptureCut::HostSettled,
                    deadline
                )
                .is_err()
        );
        assert!(
            reserve
                .finish(&authority, &owner, ProtocolCaptureCut::HostSettled)
                .is_err()
        );
    }

    #[test]
    fn native5_original_snapshot_cannot_be_claimed_by_another_owner_or_cut() {
        let (_handshake, authority) = crate::handshake::tests::authority();
        let owner = Rc::new(ProtocolCaptureOwner::new());
        let deadline =
            crate::operational_time::OperationalDeadline::after(std::time::Duration::from_secs(2))
                .unwrap();
        let mut reserve = ProtocolSnapshotReservation::reserve(1024).unwrap();
        reserve
            .bind(
                &authority,
                &owner,
                ProtocolCaptureCut::HostSettled,
                deadline,
            )
            .unwrap();
        reserve.encode(&json!({"exact": "original"})).unwrap();
        assert!(
            reserve
                .finish(
                    &authority,
                    &Rc::new(ProtocolCaptureOwner::new()),
                    ProtocolCaptureCut::HostSettled
                )
                .is_err()
        );
    }
    #[test]
    fn native5_original_snapshot_copy_geometry_refuses_before_issuer_or_encoding() {
        let source =
            crate::transport::original_frames::OriginalFrameReservation::reserve(1024, 2).unwrap();
        let mut absent = ProtocolSnapshotReservation::reserve(4096).unwrap();
        assert!(absent.validate_literal_reservation(&source).is_err());
        assert!(absent.retain_literal_history(&source).is_err());
        assert!(absent.issuer.is_none());
        assert!(absent.bytes.is_empty());
        assert!(!absent.complete);

        let different = ProtocolSnapshotReservation::reserve_complete(4096, 2048, 2).unwrap();
        assert!(different.validate_literal_reservation(&source).is_err());
        assert!(different.issuer.is_none());
        assert!(different.bytes.is_empty());
        let exact = ProtocolSnapshotReservation::reserve_complete(4096, 1024, 2).unwrap();
        exact.validate_literal_reservation(&source).unwrap();
        assert!(exact.issuer.is_none());
        assert_eq!(source.frames().count(), 0);
    }
}
