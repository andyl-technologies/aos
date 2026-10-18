//! Checks real signed storage and opaque prebirth sequencing with modeled native verification.
//!
//! The private modeled source constructor is used only by these controls. It
//! does not call a Source5 verifier or claim a native snapshot, fresh process,
//! usable restoration context, installed factory, Capture capability or Ready.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_state::{
    CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateRequirements,
};
use crucible_node_contract::{CaptureManifest, CapturedOwner, Id};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crucible-prebirth-roster-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct StoredEvidence<'a>(&'a NativeArchiveRecord);

impl CaptureEvidence for StoredEvidence<'_> {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        self.0.object_bytes(reference, maximum)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        _: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        let row = self
            .0
            .index
            .objects
            .iter()
            .find(|row| &row.reference == reference)
            .ok_or_else(|| refused("modeled dependency is absent"))?;
        if row.dependencies.len() > maximum {
            return Err(refused("modeled dependency credit"));
        }
        Ok(row.dependencies.clone())
    }

    fn verify_owner_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &CapturedOwner,
        _: &StateRequirements,
        _: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        Err(refused(
            "modeled ticket controls provide no native qualification",
        ))
    }

    fn verify_coordinator_capture(
        &self,
        _: &AdmittedGraph,
        _: &CaptureManifest,
        _: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        Err(refused(
            "modeled ticket controls provide no coordinator qualification",
        ))
    }
}

fn source(archive: NativeArchiveRecord) -> CompleteOriginalRestorationSource {
    archive.authenticate_complete_load_admission().unwrap();
    let roots = archive
        .index
        .objects
        .iter()
        .map(|row| row.reference.clone())
        .collect();
    let content = crate::node_state::closure::verify_complete_closure(
        roots,
        &StoredEvidence(&archive),
        archive.limits.state,
    )
    .unwrap();
    let administrative = archive.original_capture_journal().unwrap();
    let runtime = administrative.attempts[0].source_runtime.clone();
    let mut host: HostSchedulingContinuationRecord = serde_json::from_slice(include_bytes!(
        "core_decode_credit/fixtures/nonempty-readonly-continuation2.json"
    ))
    .unwrap();
    host.source.owner.owner.id = Id::new("model/owner/3").unwrap();
    CompleteOriginalRestorationSource {
        inner: Rc::new(CompleteOriginalSource {
            archive,
            content,
            administrative,
            host: CompleteHostArchiveRecord::InitialInvocation15(Rc::new(host)),
            runtime,
            coordinator_checkpoint: None,
            purpose: CompleteOriginalSourcePurpose::new(None),
            native_restoration_data: [None; 4],
            settled_restoration_data: std::array::from_fn(|_| None),
            restored_collection: RefCell::new(None),
            validation_limits: crate::node_contract::HostSchedulingContinuationLimits {
                maximum_record_bytes: 1024 * 1024,
                lineage: crate::node_contract::OriginalInputLineageLimits::default(),
            },
            process: std::process::id(),
            thread: thread::current().id(),
            host_issued: Cell::new(false),
            native_issued: Cell::new([false; 4]),
            target_started: Cell::new(false),
            target: RefCell::new(None),
            restoration_transactions: Cell::new(None),
        }),
    }
}

fn fixture() -> (Directory, CompleteOriginalRestorationSource) {
    let directory = Directory::new();
    let archive =
        NativeArchive::open(directory.0.join("archive"), NativeArchiveLimits::default()).unwrap();
    let source = source(archive.modeled_complete_archive_for_ticket_controls());
    (directory, source)
}

fn native_ids(source: &CompleteOriginalRestorationSource) -> Vec<Id> {
    source
        .archive()
        .owners()
        .iter()
        .filter(|row| row.owner != source.inner.host.selection_data().owner.owner.id)
        .map(|row| row.owner.clone())
        .collect()
}

#[test]
fn modeled_signed_source_missing_prebirth_ticket_sticks_without_late_issue_or_retry() {
    let (_directory, source) = fixture();
    let ids = native_ids(&source);
    let _host = source.take_host_ticket().unwrap();
    let _first = source.take_native_ticket(&ids[0]).unwrap();
    let _second = source.take_native_ticket(&ids[1]).unwrap();
    let target = Rc::new(());

    assert!(matches!(
        source.inner.bind_target(&target),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert!(source.inner.target_started.get());
    assert!(source.inner.target.borrow().is_none());
    assert_eq!(source.inner.native_issued.get(), [true, true, false, false]);
    assert!(source.take_native_ticket(&ids[2]).is_err());
    assert!(source.take_native_ticket(&ids[0]).is_err());
    assert!(source.take_host_ticket().is_err());
    assert!(source.inner.bind_target(&target).is_err());
    assert!(source.inner.authenticate_target(&target).is_err());
}

#[test]
fn modeled_signed_source_complete_roster_binds_once_and_rejects_equal_source_or_target_copies() {
    let (_directory, source) = fixture();
    let duplicate = self::source(source.archive().clone());
    let ids = native_ids(&source);
    let _host = source.take_host_ticket().unwrap();
    let tickets: Vec<_> = ids
        .iter()
        .map(|owner| source.take_native_ticket(owner).unwrap())
        .collect();
    let target = Rc::new(());

    source.inner.bind_target(&target).unwrap();
    source.inner.authenticate_target(&target).unwrap();
    assert!(source.inner.authenticate_target(&Rc::new(())).is_err());
    assert!(source.inner.bind_target(&target).is_err());
    assert!(source.take_host_ticket().is_err());
    assert_eq!(source.inner.native_issued.get(), [true, true, true, false]);
    for (ticket, owner) in tickets.iter().zip(&ids) {
        assert_eq!(&ticket.owner().unwrap().owner, owner);
        ticket.authenticate_source(&source).unwrap();
        assert!(ticket.authenticate_source(&duplicate).is_err());
        assert!(source.take_native_ticket(owner).is_err());
        assert!(
            ticket
                .content()
                .unwrap()
                .get(&ticket.owner().unwrap().state)
                .is_some()
        );
    }
    assert_eq!(source.runtime_object(), duplicate.runtime_object());
    assert_eq!(source.archive().artifact(), duplicate.archive().artifact());
}

#[test]
fn modeled_signed_source_reentrant_binding_keeps_roster_spent_and_target_closed() {
    let (_directory, source) = fixture();
    let _host = source.take_host_ticket().unwrap();
    let _tickets: Vec<_> = native_ids(&source)
        .iter()
        .map(|owner| source.take_native_ticket(owner).unwrap())
        .collect();
    let original = source.inner.target.borrow_mut();
    let target = Rc::new(());

    assert!(matches!(
        source.inner.bind_target(&target),
        Err(RuntimeError::OutstandingObligations)
    ));
    drop(original);
    assert!(source.inner.target_started.get());
    assert!(source.inner.target.borrow().is_none());
    assert!(source.inner.bind_target(&target).is_err());
    assert_eq!(source.inner.native_issued.get(), [true, true, true, false]);
}

#[test]
fn modeled_foreign_creator_refuses_before_spending_tickets_or_starting_target() {
    let (_directory, mut source) = fixture();
    let other_thread = std::thread::spawn(|| thread::current().id())
        .join()
        .unwrap();
    Rc::get_mut(&mut source.inner).unwrap().thread = other_thread;
    let owner = source.archive().owners()[0].owner.clone();

    assert!(matches!(
        source.take_native_ticket(&owner),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(matches!(
        source.take_host_ticket(),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(matches!(
        source.inner.bind_target(&Rc::new(())),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(!source.inner.target_started.get());
    assert!(!source.inner.host_issued.get());
    assert_eq!(source.inner.native_issued.get(), [false; 4]);
}

#[test]
fn ordinary_signed_source_never_passes_collecting_prebirth_owner_phase() {
    let (_directory, source) = fixture();
    let before = source.inner.capture_owned_storage().unwrap();
    assert!(matches!(
        source
            .inner
            .authenticate_collecting_prebirth_storage_phase(),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert!(!source.inner.host_issued.get());
    assert_eq!(source.inner.native_issued.get(), [false; 4]);
    assert!(!source.inner.target_started.get());
    assert!(source.inner.target.borrow().is_none());
    assert_eq!(source.inner.capture_owned_storage().unwrap(), before);
}

#[test]
fn native_ticket_does_not_infer_missing_restoration_data_from_signed_archive() {
    let (_directory, source) = fixture();
    let owners = native_ids(&source);
    let ticket = source.take_native_ticket(&owners[0]).unwrap();

    assert!(matches!(
        ticket.native_restoration_construction_data(),
        Err(RuntimeError::UnsupportedFacet)
    ));
    ticket.authenticate_source(&source).unwrap();
    assert_eq!(ticket.owner().unwrap().owner, owners[0]);
    assert!(source.take_native_ticket(&owners[0]).is_err());
    assert!(source.take_native_ticket(&owners[1]).is_ok());
}

#[test]
fn selected_transaction_spends_each_original_owner_and_cannot_enter_legacy_context() {
    let (_directory, source) = fixture();
    let ids = native_ids(&source);
    let _host = source.take_host_ticket().unwrap();
    let tickets: Vec<_> = ids
        .iter()
        .map(|owner| source.take_native_ticket(owner).unwrap())
        .collect();
    let target = Rc::new(());

    tickets[0]
        .begin_original_restoration_transaction_data(&target)
        .unwrap();

    assert!(
        tickets[0]
            .begin_original_restoration_transaction_data(&target)
            .is_err()
    );
    assert!(
        tickets[0]
            .authenticate_original_restoration_transaction_data(&Rc::new(()))
            .is_err()
    );
    assert!(
        tickets[1]
            .authenticate_original_restoration_transaction_data(&target)
            .is_err()
    );
    assert!(
        source
            .inner
            .authenticate_legacy_restoration_context_phase_data()
            .is_err()
    );
    assert!(source.inner.bind_target(&target).is_err());
    tickets[1]
        .begin_original_restoration_transaction_data(&target)
        .unwrap();
    tickets[1]
        .authenticate_original_restoration_transaction_data(&target)
        .unwrap();
    tickets[0]
        .authenticate_original_restoration_transaction_data(&target)
        .unwrap();
    assert!(source.take_native_ticket(&ids[0]).is_err());
    assert_eq!(tickets[0].owner().unwrap().owner, ids[0]);
    assert_eq!(tickets[1].owner().unwrap().owner, ids[1]);
}

#[test]
fn legacy_target_cannot_be_reinterpreted_as_a_selected_transaction() {
    let (_directory, source) = fixture();
    let _host = source.take_host_ticket().unwrap();
    let tickets: Vec<_> = native_ids(&source)
        .iter()
        .map(|owner| source.take_native_ticket(owner).unwrap())
        .collect();
    let target = Rc::new(());
    source.inner.bind_target(&target).unwrap();

    assert!(
        tickets[0]
            .begin_original_restoration_transaction_data(&target)
            .is_err()
    );
    assert!(
        tickets[0]
            .authenticate_original_restoration_transaction_data(&target)
            .is_err()
    );
    assert!(source.inner.restoration_transactions.get().is_none());
    source
        .inner
        .authenticate_legacy_restoration_context_phase_data()
        .unwrap();
    source.inner.authenticate_target(&target).unwrap();
}

#[test]
fn historical_ticket_links_actual_source_definition_and_refuses_equal_foreign_archive() {
    use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases;

    let (_directory, source) = fixture();
    let foreign = self::source(source.inner.archive().clone());
    assert_eq!(
        source.inner.archive().artifact(),
        foreign.inner.archive().artifact()
    );
    let ids = native_ids(&source);
    let ticket = source.take_native_ticket(&ids[0]).unwrap();
    assert!(matches!(
        ticket.borrowed_settled_history_data(&foreign),
        Err(RuntimeError::ForeignAuthority)
    ));
    let ticket_view = ticket.borrowed_settled_history_data(&source).unwrap();
    let source_view = source.borrowed_settled_history_data().unwrap();
    let (rows, shared) = source_view.metadata_demand_data().unwrap();
    assert!(rows > shared && shared >= 4);
    let mut slot = None;
    OriginalRestoredOwnerCapacityAliases::reserve_into(shared, &mut slot).unwrap();
    let aliases = RefCell::new(slot.unwrap());

    let definition = serde_json::to_value(source_view.with_aliases(&aliases)).unwrap();
    let edge = serde_json::to_value(ticket_view.with_aliases(&aliases)).unwrap();
    assert_eq!(definition["role"], "complete_original_source");
    assert_eq!(edge["source_role"], "complete_original_source");
    assert_eq!(definition["source_edge"], edge["source_edge"]);
    assert_eq!(edge["owner_index"], ticket.owner_index);
    assert_eq!(
        edge["manifest"],
        serde_json::to_value(source.inner.archive().artifact()).unwrap()
    );
    assert_eq!(
        definition["issuance"][0]["native_issued"][ticket.owner_index],
        true
    );
    assert!(
        definition["archive"]["index_edge"]
            .get("identity")
            .is_none()
    );
    assert!(definition["content"]["objects"].is_array());
    ticket.authenticate_source(&source).unwrap();
    assert!(source.take_native_ticket(&ids[0]).is_err());
}

#[test]
fn historical_shared_source_one_short_refuses_without_lookup_growth_or_output() {
    use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases;

    let (_directory, source) = fixture();
    let view = source.borrowed_settled_history_data().unwrap();
    let mut slot = None;
    OriginalRestoredOwnerCapacityAliases::reserve_into(1, &mut slot).unwrap();
    let aliases = RefCell::new(slot.unwrap());
    let capacity = aliases.borrow().allocated_bytes().unwrap();
    let mut output = Vec::new();

    assert!(serde_json::to_writer(&mut output, &view.with_aliases(&aliases)).is_err());
    assert!(output.is_empty());
    assert_eq!(aliases.borrow().allocated_bytes().unwrap(), capacity);
    assert!(!source.inner.host_issued.get());
    assert_eq!(source.inner.native_issued.get(), [false; 4]);
}

#[test]
fn historical_source_view_refuses_later_real_ticket_issuance_without_renewal() {
    use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases;

    let (_directory, source) = fixture();
    let ids = native_ids(&source);
    let view = source.borrowed_settled_history_data().unwrap();
    let _actual_ticket = source.take_native_ticket(&ids[0]).unwrap();
    let mut slot = None;
    OriginalRestoredOwnerCapacityAliases::reserve_into(8, &mut slot).unwrap();
    let aliases = RefCell::new(slot.unwrap());
    let mut output = Vec::new();

    assert!(serde_json::to_writer(&mut output, &view.with_aliases(&aliases)).is_err());
    assert!(output.is_empty());
    assert!(
        source
            .inner
            .native_issued
            .get()
            .into_iter()
            .any(|issued| issued)
    );
    assert!(source.take_native_ticket(&ids[0]).is_err());
}
