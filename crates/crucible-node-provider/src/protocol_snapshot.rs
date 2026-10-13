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
            issuer: None,
        })
    }

    /// Reports the actual snapshot allocation to its source-owned budget.
    pub fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
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
}

impl OriginalProtocolSnapshot {
    /// Borrows exact source-private snapshot bytes without reencoding frames.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
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
}
