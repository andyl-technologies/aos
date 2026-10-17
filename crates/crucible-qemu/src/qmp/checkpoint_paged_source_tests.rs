//! Exercises owned lazy page sources through actual Unix sockets and workers.
//!
//! These component tests retain immutable model bytes and verify real service
//! responses. They do not run QEMU, install missing guest pages, or qualify
//! native checkpoint equivalence, memory removal, or low-residency execution.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use crate::ram_source::{QemuRamBacking, QemuRamSourceService};
use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use crucible_protocol::ram_page::{
    RamPageBinding, RamPageRequest, RamPageResponse, RamPageStatus, read_ram_page_response,
};
use crucible_ram::PageProof;

use super::checkpoint_paged_source_support as support;
use support::ImmutableBacking;

fn binding(backing: &dyn QemuRamBacking, owner: u8) -> RamPageBinding {
    RamPageBinding {
        session: [owner; 16],
        owner_incarnation: [owner.wrapping_add(1); 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    }
}

fn source(
    backing: Arc<ImmutableBacking>,
    owner: u8,
) -> Result<(QemuRamSourceService, UnixStream), Box<dyn Error>> {
    let (server, client) = UnixStream::pair()?;
    client.set_read_timeout(Some(Duration::from_secs(2)))?;
    client.set_write_timeout(Some(Duration::from_secs(2)))?;
    let namespace = binding(backing.as_ref(), owner);
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(10)),
    )?;
    let service = QemuRamSourceService::start(
        server,
        backing,
        namespace,
        supervisor,
        crucible_linux_resource::host_services::HostServiceAllocator::new(1, 4, 8 * 1024 * 1024)?,
    )?;
    Ok((service, client))
}

fn request(
    client: &mut UnixStream,
    binding: RamPageBinding,
    sequence: u64,
    page_index: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    client.write_all(
        &RamPageRequest {
            binding,
            sequence,
            region_ordinal: 0,
            page_index,
        }
        .encode()?,
    )?;
    Ok(read_ram_page_response(client)?)
}

#[test]
fn paged_source_serves_complete_partial_pages_with_authenticated_proofs()
-> Result<(), Box<dyn Error>> {
    let backing = Arc::new(ImmutableBacking::new(2)?);
    let (service, mut client) = source(Arc::clone(&backing), 1)?;
    for (sequence, page_index, expected) in [
        (1, 0, vec![1; 4096]),
        (2, 1, vec![2; 4096]),
        (3, 2, vec![3; 19]),
    ] {
        let bytes = request(&mut client, service.binding(), sequence, page_index)?;
        let response = RamPageResponse::decode(&bytes)?;
        assert_eq!(response.binding, service.binding());
        assert_eq!(response.sequence, sequence);
        assert_eq!(response.status, RamPageStatus::Page);
        assert_eq!(response.page, expected);
        let proof = PageProof::decode(response.proof, crucible_ram::Limits::default())?;
        proof.verify(
            response.page,
            backing.root_record(),
            backing.root_record().digest(),
        )?;
    }
    service.check_health()?;
    service.stop()?;
    Ok(())
}

#[test]
fn paged_source_preserves_partial_frame_across_polling() -> Result<(), Box<dyn Error>> {
    let backing = Arc::new(ImmutableBacking::new(2)?);
    let (service, mut client) = source(Arc::clone(&backing), 17)?;
    let first = RamPageRequest {
        binding: service.binding(),
        sequence: 1,
        region_ordinal: 0,
        page_index: 2,
    }
    .encode()?;

    client.write_all(&first[..17])?;
    // Cross the service polling interval with an incomplete frame; its cursor
    // must survive the timeout before the remaining authenticated bytes arrive.
    thread::sleep(Duration::from_millis(35));
    client.write_all(&first[17..])?;
    let bytes = read_ram_page_response(&mut client)?;
    let response = RamPageResponse::decode(&bytes)?;
    assert_eq!(response.status, RamPageStatus::Page);
    assert_eq!(response.sequence, 1);
    assert_eq!(response.page, vec![3; 19]);
    PageProof::decode(response.proof, crucible_ram::Limits::default())?.verify(
        response.page,
        backing.root_record(),
        backing.root_record().digest(),
    )?;

    let next = request(&mut client, service.binding(), 2, 0)?;
    assert_eq!(RamPageResponse::decode(&next)?.page, vec![1; 4096]);
    service.stop()?;
    Ok(())
}

#[test]
fn independently_owned_sources_preserve_predecessor_and_changed_images()
-> Result<(), Box<dyn Error>> {
    let parent = Arc::new(ImmutableBacking::new(2)?);
    let child = Arc::new(ImmutableBacking::new(0x7f)?);
    assert_ne!(parent.root_record().digest(), child.root_record().digest());
    let (parent_service, mut parent_client) = source(parent, 3)?;
    let (child_service, mut child_client) = source(child, 5)?;
    let parent_bytes = request(&mut parent_client, parent_service.binding(), 1, 1)?;
    let child_bytes = request(&mut child_client, child_service.binding(), 1, 1)?;
    assert_eq!(RamPageResponse::decode(&parent_bytes)?.page, vec![2; 4096]);
    assert_eq!(
        RamPageResponse::decode(&child_bytes)?.page,
        vec![0x7f; 4096]
    );
    parent_service.stop()?;
    child_service.stop()?;
    Ok(())
}

#[test]
fn paged_source_rejects_corrupt_bytes_before_response_publication() -> Result<(), Box<dyn Error>> {
    let backing = Arc::new(ImmutableBacking::new(2)?);
    let (service, mut client) = source(Arc::clone(&backing), 7)?;
    let original = request(&mut client, service.binding(), 1, 1)?;
    assert_eq!(RamPageResponse::decode(&original)?.page, vec![2; 4096]);
    backing.corrupt_reads.store(true, Ordering::Release);
    assert!(request(&mut client, service.binding(), 2, 1).is_err());
    let failure = service
        .stop()
        .err()
        .ok_or("corrupt backing source stopped successfully")?;
    assert!(failure.source.to_string().contains("proof validation"));
    assert!(Arc::strong_count(&backing) >= 2);
    drop(failure);
    Ok(())
}

#[test]
fn paged_source_rejects_stale_owner_and_repeated_sequences() -> Result<(), Box<dyn Error>> {
    for stale_owner in [true, false] {
        let (service, mut client) = source(Arc::new(ImmutableBacking::new(2)?), 9)?;
        request(&mut client, service.binding(), 1, 0)?;
        let mut namespace = service.binding();
        if stale_owner {
            namespace.owner_incarnation = [0x55; 16];
        }
        let bytes = request(&mut client, namespace, if stale_owner { 2 } else { 1 }, 0)?;
        let refused = RamPageResponse::decode(&bytes)?;
        assert_eq!(refused.status, RamPageStatus::Rejected);
        assert_eq!(refused.binding, service.binding());
        assert!(refused.page.is_empty());
        assert!(service.stop().is_err());
    }
    Ok(())
}

#[test]
fn paged_source_child_requires_private_namespace_and_retains_backing() -> Result<(), Box<dyn Error>>
{
    let backing = Arc::new(ImmutableBacking::new(2)?);
    let weak = Arc::downgrade(&backing);
    let (service, _client) = source(Arc::clone(&backing), 11)?;
    let fresh = binding(backing.as_ref(), 13);
    assert!(service.child_backing(service.binding()).is_err());
    let mut same_owner = fresh;
    same_owner.owner_incarnation = service.binding().owner_incarnation;
    assert!(service.child_backing(same_owner).is_err());
    let mut same_session = fresh;
    same_session.session = service.binding().session;
    assert!(service.child_backing(same_session).is_err());
    let mut wrong_root = fresh;
    wrong_root.root_digest[0] ^= 1;
    assert!(service.child_backing(wrong_root).is_err());
    let retained = service.child_backing(fresh)?;
    drop(backing);
    service.stop()?;
    assert!(weak.upgrade().is_some());
    drop(retained);
    assert!(weak.upgrade().is_none());
    Ok(())
}

#[test]
fn paged_source_cancellation_closes_admission_and_releases_after_join() -> Result<(), Box<dyn Error>>
{
    let backing = Arc::new(ImmutableBacking::new(2)?);
    let weak = Arc::downgrade(&backing);
    let (service, mut client) = source(backing, 15)?;
    service.cancel();
    assert!(request(&mut client, service.binding(), 1, 0).is_err());
    assert!(weak.upgrade().is_some());
    service.stop()?;
    assert!(weak.upgrade().is_none());
    Ok(())
}
