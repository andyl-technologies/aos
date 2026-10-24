//! Archive completion remains subject to its original receiver admission.
//!
//! A published and reloaded production checkpoint authenticates the owning
//! whole-world root and RAM binding. These finite component controls exercise
//! archive storage only, without launching or admitting a destination machine.

use super::*;

use std::error::Error;
use std::sync::atomic::AtomicBool;

use crucible_qemu_protocol::ram_transfer::{RamTransferControl, RamTransferLimits};
use crucible_store::content_store::{DurabilityRequirement, MemoryRefBackend};
use crucible_store::owned_decode::{DecodeBudget, ResourceLoan};
use crucible_store::ram::{
    FencedRamRetention, RamRetentionAuthority, RamTransferReceiver, RamTransferSender,
    RamTransferStep,
};

#[derive(Debug, thiserror::Error)]
#[error("archive receiver's original admission was revoked")]
struct RevokedReceiver;

struct ReceiverResources {
    resources: Arc<dyn StorePhysicalQuotaGuard>,
    revoked: AtomicBool,
}

impl StorePhysicalQuotaGuard for ReceiverResources {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.resources.decoded_metadata_limit()
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        self.resources
            .reserve_resources(descriptors, resident_bytes)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(StoreError::Supervision {
                source: Box::new(RevokedReceiver),
            });
        }
        self.resources.verify()
    }
}

struct ReceiverRetention {
    publication: FencedRamRetention,
    caller: Arc<ReceiverResources>,
    revoke: bool,
    issued: Mutex<Option<ContentId>>,
}

impl RamRetention for ReceiverRetention {
    fn retain_object(&self, id: ContentId) -> Result<(), RamStoreError> {
        self.publication.retain_object(id)
    }

    fn retain_root(&self, root: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        let lease = self.publication.retain_root(root)?;
        assert!(
            self.issued
                .lock()
                .expect("issued root lock")
                .replace(root)
                .is_none()
        );
        if self.revoke {
            self.caller.revoked.store(true, Ordering::SeqCst);
        }
        Ok(lease)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Revocation {
    None,
    Retention,
    Acknowledgment,
}

fn receive_authenticated_archive(revocation: Revocation) {
    let _decode_scope = crate::exact_checkpoint_store::test_support::fixture_decode_scope();
    let directory = tempfile::tempdir().expect("archive component directory");
    let fixture = crate::build_exact_ram_production_checkpoint_codec_fixture(
        &directory.path().join("fixture"),
    )
    .expect("complete persistent checkpoint fixture");
    let source_backend = Arc::new(DirectoryBlobBackend::new(
        "receiver-admission-source",
        directory.path().join("source"),
    ));
    let source_retention = RamRetentionAuthority::new(Arc::new(MemoryRefBackend::new()));
    let checkpoint_store =
        ExactCheckpointStore::new(source_backend, 1 << 30, source_retention.clone())
            .expect("exact checkpoint store")
            .with_ram_root_resources(
                crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
                    .expect("finite checkpoint resources"),
            );
    let prepared = checkpoint_store
        .prepare_production_closure(fixture.closure().clone())
        .expect("prepare complete checkpoint");
    let checkpoint = checkpoint_store
        .publish_production_closure(&prepared)
        .expect("publish complete checkpoint")
        .root();
    let loaded = checkpoint_store
        .load_production_closure(checkpoint)
        .expect("authenticate whole-world checkpoint and RAM binding");
    assert_eq!(loaded.root(), checkpoint);
    assert_eq!(loaded.paged_ram_root_ids().len(), 1);
    let source_publication = source_retention.acquire().expect("source GC fence");
    let source_lease = source_publication
        .retain_root(loaded.paged_ram_root_ids()[0])
        .expect("independent source RAM claim");
    let (source, root, source_original) = loaded
        .open_paged_ram(0, source_lease, &mut || Ok(()))
        .expect("open the authenticated checkpoint's RAM source");
    drop(source_publication);

    let backend_resources =
        crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
            .expect("independent finite destination backend resources");
    let destination_backend = DirectoryBlobBackend::new_with_physical_quota(
        "receiver-admission-destination",
        directory.path().join("destination"),
        backend_resources.clone(),
    )
    .expect("durable component destination");
    let destination = RamStore::new(
        destination_backend.clone(),
        DurabilityRequirement::new(1, false).expect("archive durability"),
        RamStoreLimits::default(),
    )
    .expect("destination RAM store");
    let caller = Arc::new(ReceiverResources {
        resources: crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
            .expect("independent finite receiver resources"),
        revoked: AtomicBool::new(false),
    });
    let original = DecodeBudget::for_store(caller.clone()).expect("receiver original account");
    original
        .charge_bytes(crucible_store::ram::maximum_ram_root_decoding_bytes().expect("root bound"))
        .expect("prepay the existing complete root decoder bound");
    let destination_retention = RamRetentionAuthority::new(Arc::new(MemoryRefBackend::new()));
    let retention = ReceiverRetention {
        publication: destination_retention
            .acquire()
            .expect("destination GC fence"),
        caller: caller.clone(),
        revoke: revocation == Revocation::Retention,
        issued: Mutex::new(None),
    };
    let mut sender = RamTransferSender::new(
        source,
        root.clone(),
        [119; 32],
        checkpoint.content_id(),
        "receiver-admission-destination",
        1,
        RamTransferLimits {
            objects: 100_000,
            bytes: 64 << 20,
            chunk_bytes: 4096,
        },
        &source_original,
    )
    .expect("sender bound to the authenticated whole-world checkpoint");
    let offer = sender.offer().expect("originally credited archive offer");
    let mut receiver = RamTransferReceiver::new(destination, &retention, offer)
        .expect("admit the authenticated archive offer");
    let mut acknowledgments = 0;
    let result = receiver.receive(
        &mut |message| {
            let acknowledging = matches!(message.control, RamTransferControl::ClosureStored { .. });
            let response = sender.respond(message, &mut || Ok(()))?;
            if acknowledging {
                acknowledgments += 1;
                if revocation == Revocation::Acknowledgment {
                    caller.revoked.store(true, Ordering::SeqCst);
                }
            }
            Ok(response)
        },
        &original,
        &mut || Ok(()),
    );

    let issued = retention
        .issued
        .lock()
        .expect("issued root lock")
        .expect("actual root lease");
    assert_eq!(issued, root.object_id());
    let backend_original = DecodeBudget::for_store(backend_resources.clone())
        .expect("independently live backend original");
    let bytes = destination_backend
        .read_with_boundary(&backend_original, issued, None, &mut || Ok(()))
        .expect("read the actual durable destination root")
        .read_all_with_boundary(&backend_original, 8192, &mut || Ok(()))
        .expect("canonical root bytes");
    assert!(issued.authenticates(&bytes));
    drop(bytes);
    drop(backend_original);
    assert_eq!(
        acknowledgments,
        usize::from(revocation != Revocation::Retention)
    );
    drop(receiver);

    if revocation == Revocation::None {
        let RamTransferStep::ClosureStored(stored) = result.expect("live archive completion")
        else {
            panic!("successful archive must produce its stored closure");
        };
        assert_eq!(stored.root().object_id(), root.object_id());
        assert_eq!(stored.root().logical_digest(), root.logical_digest());
        drop(stored);
        drop(original);
    } else {
        let error = result.expect_err("a revoked receiver cannot accept completion");
        let mut cause: Option<&(dyn Error + 'static)> = Some(&error);
        while let Some(current) = cause {
            if current.is::<RevokedReceiver>() {
                break;
            }
            cause = current.source();
        }
        assert!(
            cause.is_some(),
            "retain the original receiver's typed cause"
        );
        drop(original);
        assert!(
            caller
                .resources
                .reserve_resources(
                    0,
                    crate::exact_checkpoint_store::test_support::FIXTURE_RESIDENT_BYTES,
                )
                .is_err(),
            "the error retains its original account after caller close"
        );
        drop(error);
    }
    let released = caller
        .resources
        .reserve_resources(
            0,
            crate::exact_checkpoint_store::test_support::FIXTURE_RESIDENT_BYTES,
        )
        .expect("final result close releases all receiver credit");
    drop(released);
    assert!(backend_resources.verify().is_ok());
}

#[test]
fn live_receiver_acknowledges_the_authenticated_archive() {
    receive_authenticated_archive(Revocation::None);
}

#[test]
fn receiver_revoked_during_retention_refuses_before_stored_acknowledgment() {
    receive_authenticated_archive(Revocation::Retention);
}

#[test]
fn receiver_revoked_during_stored_exchange_refuses_completion() {
    receive_authenticated_archive(Revocation::Acknowledgment);
}
