//! Supplies actual selected images and expiry-based collector takeover fixtures.

use crate::bucket::held::SingleHeld;
use crate::gc::runner::copied_retirement_tests::support::CopiedFixture;
use crate::gc::runner::permanent_local::Recovery;
use crate::pack::{EntryKind, PackClass, PackWriter};
use crate::store::{Clock, NativeEffectClock};
use std::collections::BTreeMap;
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationState, PublicationTransaction,
};
use terrane_format::gc::retirement::{
    OperationPhase, OwnershipSlot, PermanentDeleteAuthorization, PermanentDeleteOperation,
    PermanentDeletePass, PermanentOwnerSelection,
};
use terrane_format::gc::{GcLease, Windows};

/// Names the independent source plaintext encoded by the copied fixture.
pub(super) const OLD_BODY: &[u8] = b"unreachable copied old body";

/// Borrows the actual fixture's native Guard and current collector Session.
pub(super) type NativeRecovery<'a> = Recovery<
    'a,
    crate::gc::runner::copied_retirement_tests::fs::CopiedFs,
    NativeEffectClock,
    crate::repository::MetadataValidator,
    NativeEffectClock,
>;

/// Captures complete selected semantics and independently decoded progress.
pub(super) struct Image {
    /// Complete selected publication state.
    pub(super) state: PublicationState,
    /// Exact complete selected logical projection.
    pub(super) logical: BTreeMap<String, Option<Vec<u8>>>,
    /// Independently decoded current generation manifest.
    pub(super) manifest: GenerationManifest,
    /// Independently decoded selected capabilities.
    pub(super) capabilities: BucketCapabilities,
    /// Actual selected operation key for the permanently owned family.
    pub(super) owner_key: Option<String>,
    /// Actual selected typed mutable operation.
    pub(super) operation: Option<PermanentDeleteOperation>,
    /// Independently checked original selecting slot for the permanent owner.
    pub(super) owner_slot: Option<OwnershipSlot>,
    /// Independently hash-checked selected protected event.
    pub(super) pass: Option<PermanentDeletePass>,
}

/// Reads complete actual selected state and protected progress.
///
/// # Panics
/// Panics if actual fixture I/O, production qualification or an independent assertion fails.
pub(super) async fn image(fixture: &CopiedFixture) -> Image {
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let capabilities =
        BucketCapabilities::decode(observed.logical()["CAPABILITIES"].as_deref().unwrap()).unwrap();
    let manifest = GenerationManifest::decode(
        observed.logical()[&format!(
            "objects/index/{}/MANIFEST",
            capabilities.generation.unwrap()
        )]
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let selected = observed.logical().iter().find_map(|(key, bytes)| {
        if !key.contains("/delete/") {
            return None;
        }
        let operation = PermanentDeleteOperation::decode(bytes.as_deref()?).ok()?;
        (operation.authorization.exclusion().pack == *fixture.pack.as_bytes())
            .then_some((key.clone(), operation))
    });
    let (owner_key, operation) = selected.map_or((None, None), |(key, operation)| {
        (Some(key), Some(operation))
    });
    let owner_slot = operation.as_ref().map(|operation| {
        let authorization = &operation.authorization;
        let selector = observed
            .state()
            .burn_owners
            .as_ref()
            .unwrap()
            .iter()
            .find(|row| row.pack == authorization.exclusion().pack)
            .unwrap();
        let PermanentOwnerSelection::Permanent(pointer) = &selector.selection else {
            panic!("fixture lacks actual permanent owner selection");
        };
        assert_eq!(pointer.key, *owner_key.as_ref().unwrap());
        assert_eq!(
            pointer.digest,
            *blake3::hash(&authorization.encode().unwrap()).as_bytes()
        );
        let fence = match authorization {
            PermanentDeleteAuthorization::Sweep(value) => &value.fence,
            PermanentDeleteAuthorization::Copied(value) => &value.fence,
        };
        let revision = fence
            .key
            .rsplit('/')
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            .checked_add(1)
            .unwrap();
        let control = fixture.source.parent.join("copied-publication");
        let physical = |key: &str| {
            observed
                .physical_reads()
                .iter()
                .find(|read| read.path() == control.join(key))
                .unwrap()
                .bytes()
                .unwrap()
        };
        let slot_key = format!("publication/commits/{revision}");
        let bytes = physical(&slot_key);
        let commit = PublicationCommit::decode(bytes).unwrap();
        let transaction_bytes = physical(&commit.transaction_key);
        commit
            .check_transaction(&slot_key, transaction_bytes)
            .unwrap();
        let transaction = PublicationTransaction::decode(transaction_bytes).unwrap();
        assert_eq!(transaction.new.revision, revision);
        assert_eq!(transaction.new.binding, observed.state().binding);
        let PublicationProof::PermanentRetirement {
            authorization: selected_authorization,
            ..
        } = &transaction.proof
        else {
            panic!("fixture lacks actual permanent selecting proof");
        };
        assert_eq!(*selected_authorization, authorization.encode().unwrap());
        assert!(
            transaction
                .new
                .burn_owners
                .as_ref()
                .unwrap()
                .contains(selector)
        );
        let initial = transaction
            .changes
            .iter()
            .find(|change| change.key == *owner_key.as_ref().unwrap())
            .unwrap()
            .new
            .as_deref()
            .unwrap();
        let initial = PermanentDeleteOperation::decode(initial).unwrap();
        assert_eq!(initial.authorization, *authorization);
        assert_eq!(initial.phase, OperationPhase::Proposed);
        assert!(initial.owner.is_none());
        assert!(initial.pass.is_none());
        let slot = OwnershipSlot {
            revision,
            digest: *blake3::hash(bytes).as_bytes(),
        };
        authorization.check_owner_slot(&slot).unwrap();
        slot
    });
    let pass = if let Some(pointer) = operation
        .as_ref()
        .and_then(|operation| operation.pass.as_ref())
    {
        let control = fixture.source.parent.join("copied-publication");
        let bytes = tokio::fs::read(control.join(&pointer.key)).await.unwrap();
        assert_eq!(*blake3::hash(&bytes).as_bytes(), pointer.digest);
        operation
            .as_ref()
            .unwrap()
            .check_pass(&bytes, owner_key.as_deref().unwrap())
            .unwrap();
        Some(PermanentDeletePass::decode(&bytes).unwrap())
    } else {
        None
    };
    Image {
        state: observed.state().clone(),
        logical: observed.logical().clone(),
        manifest,
        capabilities,
        owner_key,
        operation,
        owner_slot,
        pass,
    }
}

/// Acquires a new whole lease after the actual selected lease expires.
///
/// # Panics
/// Panics if actual fixture I/O, production qualification or an independent assertion fails.
pub(super) async fn takeover<'a>(fixture: &'a CopiedFixture, holder: &str) -> NativeRecovery<'a> {
    let selected = image(fixture).await;
    let lease = GcLease::decode(selected.logical["gc/lease"].as_deref().unwrap()).unwrap();
    let ticks = fixture
        .source
        .clock
        .monotonic()
        .as_secs()
        .checked_add(1)
        .unwrap();
    fixture
        .source
        .clock
        .set(lease.expiry.checked_add(1).unwrap(), ticks);
    Recovery::start(
        fixture.guard(),
        &fixture.authority,
        holder.into(),
        90,
        fixture.repository.coordinator(),
        Windows::new(30, 60, 60, 90).unwrap(),
    )
    .await
    .unwrap()
}

/// Installs the independently reconstructed canonical source index.
///
/// # Panics
/// Panics if actual fixture I/O, production qualification or an independent assertion fails.
pub(super) async fn install_source_index(fixture: &CopiedFixture) {
    let mut writer = PackWriter::new(fixture.pack, PackClass::Data, false);
    writer.append_raw(EntryKind::Chunk, OLD_BODY).unwrap();
    let sealed = writer.seal().unwrap();
    let root = fixture.guard().store().root();
    assert_eq!(
        tokio::fs::read(root.join(fixture.pack.pack_key()))
            .await
            .unwrap(),
        sealed.bytes()
    );
    tokio::fs::write(root.join(fixture.pack.index_key()), sealed.index_object())
        .await
        .unwrap();
}

/// Checks exact immutable ownership and all unaffected selected authority.
///
/// # Panics
/// Panics if actual fixture I/O, production qualification or an independent assertion fails.
pub(super) fn assert_owner_retained(before: &Image, after: &Image) {
    assert_eq!(after.state.burn_owners, before.state.burn_owners);
    assert_eq!(after.state.binding, before.state.binding);
    assert_eq!(after.state.branches, before.state.branches);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.sources, before.state.sources);
    assert_eq!(after.manifest.burns, before.manifest.burns);
    assert_eq!(after.manifest.exclusions, before.manifest.exclusions);
    assert_eq!(after.owner_slot, before.owner_slot);
    let owner_slot = before.owner_slot.unwrap();
    let before = before.operation.as_ref().unwrap();
    let after = after.operation.as_ref().unwrap();
    assert_eq!(after.authorization, before.authorization);
    if before.owner.is_some() {
        assert_eq!(after.owner, before.owner);
    }
    for operation in [before, after] {
        if let Some(owner) = operation.owner {
            assert_eq!(owner, owner_slot);
        } else {
            // The initial proposal cannot hash its own future selecting slot.
            assert_eq!(operation.phase, OperationPhase::Proposed);
            assert!(operation.pass.is_none());
        }
    }
}

/// Reopens actual native storage and independently checks retained selection.
///
/// # Panics
/// Panics on native reopen refusal or a changed owner, inventory or selected pass.
pub(super) async fn reopen_checked(fixture: CopiedFixture, before: &Image) -> CopiedFixture {
    let fixture = fixture.reopen().await;
    let after = image(&fixture).await;
    assert_owner_retained(before, &after);
    assert_eq!(after.manifest, before.manifest);
    assert_eq!(after.operation, before.operation);
    assert_eq!(after.pass, before.pass);
    fixture
}

/// Removes genuine private fixture storage after worker completion.
///
/// # Panics
/// Panics if actual fixture I/O, production qualification or an independent assertion fails.
pub(super) fn cleanup(fixture: CopiedFixture) {
    let CopiedFixture {
        source,
        repository,
        authority,
        ..
    } = fixture;
    drop(authority);
    drop(repository);
    source.cleanup();
}
