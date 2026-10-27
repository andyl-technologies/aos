//! Final transport acknowledgment funding retains the explicit receiver owner.
//!
//! A real sender supplies portable frames to the receiver. Revocation begins
//! after destination retention, at the acknowledgment's scratch reservation.
//! These finite component accounts grant no Native execution authority.

use super::*;
use crucible_qemu_protocol::ram_transfer::{RamTransferControl, RamTransferMessage};
use std::io::{Cursor, Read, Write};

struct PeerTransport {
    sender: RamTransferSender,
    original: DecodeBudget,
    request: Vec<u8>,
    response: Cursor<Vec<u8>>,
    requests: usize,
    acknowledgments: usize,
    cancellations: usize,
}

impl Read for PeerTransport {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.response.read(bytes)
    }
}

impl Write for PeerTransport {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.request.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // The fixture peer decodes and responds under its independent Source.
        let _scope = self.original.enter();
        let request = RamTransferMessage::decode(&self.request).map_err(std::io::Error::other)?;
        match request.control {
            RamTransferControl::ClosureStored { .. } => self.acknowledgments += 1,
            RamTransferControl::Cancel => self.cancellations += 1,
            _ => self.requests += 1,
        }
        let response = self
            .sender
            .respond(request, &mut || Ok(()))
            .map_err(std::io::Error::other)?;
        self.response = Cursor::new(
            response
                .with_encoded(&self.original, |bytes| Ok(bytes.to_vec()))
                .map_err(std::io::Error::other)?,
        );
        self.request.clear();
        Ok(())
    }
}

struct AcknowledgmentRetention {
    inner: Retention,
    revoke: Option<Arc<ObservedQuota>>,
    roots: AtomicU64,
}

impl RamRetention for AcknowledgmentRetention {
    fn retain_object(&self, id: ContentId) -> Result<(), RamStoreError> {
        self.inner.retain_object(id)
    }

    fn retain_root(&self, root: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        let lease = self.inner.retain_root(root)?;
        self.roots.fetch_add(1, Ordering::SeqCst);
        if let Some(quota) = &self.revoke {
            // Allow the existing post-retention live check, then refuse the
            // actual scratch reservation before the acknowledgment is written.
            quota.revoke_after_verifications.store(2, Ordering::SeqCst);
        }
        Ok(lease)
    }
}

fn exercise_acknowledgment_funding(revoke: bool) {
    let source_directory = tempfile::tempdir().unwrap();
    let destination_directory = tempfile::tempdir().unwrap();
    let source_quota = ObservedQuota::with_limit(32 << 20);
    let destination_quota = ObservedQuota::with_limit(32 << 20);
    let source = directory_store(source_directory.path(), &source_quota);
    let destination = directory_store(destination_directory.path(), &destination_quota);
    let source_original = fixture_original(&source);
    let destination_original = fixture_original(&destination);
    let root = source
        .capture(
            topology(17),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &source_original,
            &mut || Ok(()),
        )
        .unwrap();
    let root_id = root.object_id();
    let offer = archive_offer(&root, 64);
    let mut sender = RamTransferSender::new(
        source,
        root,
        [96; 32],
        ContentId::parse(&offer.whole_world_root).unwrap(),
        &offer.destination,
        offer.durable_placements,
        offer.limits,
        &source_original,
    )
    .unwrap();
    let response = crate::ram::response::decode_local(
        &sender.offer().unwrap(),
        &source_original,
        &destination_original,
    )
    .unwrap();

    let quota = ObservedQuota::with_limit(128 << 20);
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original.charge_bytes(8197).unwrap();
    let admitted = quota.used();
    let retention = AcknowledgmentRetention {
        inner: Retention::default(),
        revoke: revoke.then(|| quota.clone()),
        roots: AtomicU64::new(0),
    };
    let mut receiver = RamTransferReceiver::new(destination.clone(), &retention, response).unwrap();
    let mut transport = PeerTransport {
        sender,
        original: source_original,
        request: Vec::new(),
        response: Cursor::new(Vec::new()),
        requests: 0,
        acknowledgments: 0,
        cancellations: 0,
    };
    let foreign_quota = ObservedQuota::new();
    let foreign = DecodeBudget::for_store(foreign_quota.clone()).unwrap();
    foreign.charge_bytes(239).unwrap();
    let foreign_requests = foreign_quota.reservations.load(Ordering::SeqCst);
    let scope = foreign.enter();

    let result = receiver.receive_transport(&mut transport, &original, &mut || Ok(()));

    assert!(transport.requests > 0);
    assert_eq!(transport.cancellations, 0);
    assert_eq!(retention.roots.load(Ordering::SeqCst), 1);
    {
        let _inspection = destination_original.enter();
        assert!(destination.backend.contains(root_id).unwrap());
    }
    if revoke {
        let error = result.unwrap_err();
        let mut cause = Some(&error as &(dyn Error + 'static));
        let mut actual_revocation = false;
        while let Some(current) = cause {
            actual_revocation |= current.is::<RevokedOriginalAuthority>();
            cause = current.source();
        }
        assert!(actual_revocation);
        assert!(quota.revoked.load(Ordering::SeqCst));
        assert_eq!(transport.acknowledgments, 0);
        drop(receiver);
        drop(scope);
        drop(foreign);
        drop(original);
        let retained = (quota.used(), foreign_quota.used());
        drop(error);
        assert_eq!((quota.used(), foreign_quota.used()), (0, 0));
        assert_eq!(retained, (admitted, 0));
    } else {
        let RamTransferStep::ClosureStored(stored) = result.unwrap() else {
            panic!("complete RAM closure");
        };
        assert_eq!(stored.root().object_id(), root_id);
        assert_eq!(stored.report().copied_objects, 3);
        assert_eq!(transport.acknowledgments, 1);
        drop(stored);
        drop(receiver);
        drop(scope);
        drop(foreign);
        drop(original);
        assert_eq!((quota.used(), foreign_quota.used()), (0, 0));
    }
    assert_eq!(
        foreign_quota.reservations.load(Ordering::SeqCst),
        foreign_requests
    );
}

#[test]
fn receiver_transport_preserves_healthy_acknowledgment() {
    exercise_acknowledgment_funding(false);
}

#[test]
fn receiver_transport_acknowledgment_refusal_retains_explicit_original() {
    exercise_acknowledgment_funding(true);
}
