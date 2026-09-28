//! Pure consumer-interest replay and closed retirement fixtures.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_protocol::semantics::CatalogBindingV1;
use aos_sandbox_source_provider_protocol::{
    AcquireSourceRequestV1, ProviderHeldSnapshotCatalogV1, ProviderHeldSnapshotRowV1,
    RecursiveTopologyProofV1, SourceProviderKeyUsageV1, SourceProviderMethod,
    SourceProviderProofV1, SourceProviderSigningKeyV1, SourceRootObservationV1, SourceUseV1,
    StorageNativeAcquireRequestV2, StorageZfsHoldTransportRequestV1, digest_logical_binding_bytes,
    encode_acquire_request, prospective_mount_apply_template_digest_v1, sign_request,
    source_acquisition_id_v2,
};
use ed25519_dalek::SigningKey;

use super::*;
use crate::root_policy::PortableRootAttributesV1;
use crate::snapshot_metadata::CheckedSnapshotMetadataRecordV1;
use crate::{HoldId, ManagedDatasetRoot, ResolvedDataset, ResolvedSnapshot, StorageDomainsV1};

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

pub(super) fn fixture(sequence: u8, challenge: u8) -> PreparedStorageNativeIssuanceV1 {
    let domains = StorageDomainsV1::new(digest(1), digest(2), digest(3), digest(4)).unwrap();
    let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 11).unwrap();
    let source =
        ResolvedDataset::from_catalog(root, "tank/aos/workspace", 22, [5; 32], domains).unwrap();
    let snapshot = ResolvedSnapshot::from_catalog(source, "revision", 33, [6; 32]).unwrap();
    let catalog = CatalogBindingV1::from_publisher(9, digest(11)).unwrap();
    let metadata = CheckedSnapshotMetadataRecordV1::new_for_test(
        [12; 16],
        digest(13),
        digest(14),
        catalog,
        33,
        22,
        [5; 32],
        digest(15),
        PortableRootAttributesV1::new(0, 0, 0o755).unwrap(),
        0,
        0,
        1,
        0,
        digest(16),
    )
    .unwrap();
    let cut = StorageHeldSnapshotCatalogCutV1 {
        snapshot,
        metadata,
        storage_version: 1,
        hold_generation: 9,
        hold_id: HoldId::from_bytes([7; 16]).unwrap(),
        active_hold_digest: digest(8),
        root_policy_digest: digest(9),
        catalog,
        authority_sequence: 10,
        materialized_state_digest: digest(10),
    };

    let binding = b"native-fixture".to_vec();
    let binding_digest = digest_logical_binding_bytes(&binding);
    let proof = ZfsHeldSnapshotProofV1::new(
        [5; 32],
        1,
        44,
        22,
        33,
        [7; 16],
        9,
        digest(8),
        digest(9),
        digest(17),
    )
    .unwrap();
    let canonical_proof = SourceProviderProofV1::ZfsHeldSnapshot {
        proof: proof.clone(),
        topology: RecursiveTopologyProofV1::new([45; 16], 1, digest(46), 1, 0, 1, 0).unwrap(),
    };
    let native_row = ProviderHeldSnapshotRowV1::new(
        binding_digest,
        [18; 32],
        1,
        digest(19),
        1,
        digest(20),
        proof,
    )
    .unwrap();
    let native_catalog =
        ProviderHeldSnapshotCatalogV1::new(1, digest(21), vec![native_row]).unwrap();

    let holder = [22; 16];
    let holder_generation = 1;
    let holder_digest = digest(23);
    let acquisition =
        source_acquisition_id_v2(holder, holder_generation, holder_digest, sequence.into());
    let mut template = Vec::new();
    for tag in 1_u8..=27 {
        let value = match tag {
            1 => b"AOSMSEM1".to_vec(),
            2 => 1_u16.to_be_bytes().to_vec(),
            _ => vec![tag, tag.wrapping_add(1)],
        };
        template.push(tag);
        template.extend_from_slice(&(value.len() as u32).to_be_bytes());
        template.extend_from_slice(&value);
    }
    let template_digest = prospective_mount_apply_template_digest_v1(&template).unwrap();
    let root_request = AcquireSourceRequestV1::new_with_acquisition_sequence(
        digest(24),
        1,
        [sequence; 16],
        acquisition,
        sequence.into(),
        template,
        template_digest,
        SourceUseV1::MountCreate,
        [25; 16],
        [26; 16],
        holder,
        holder_generation,
        holder_digest,
        binding,
        binding_digest,
        160,
        60,
        digest(27),
        false,
        0,
        false,
    )
    .unwrap();
    assert_eq!(
        root_request.kernel_coupled(),
        canonical_proof.requires_kernel_coupled()
    );
    let root_key = SigningKey::from_bytes(&[28; 32]);
    let root_signer = SourceProviderSigningKeyV1::for_signing_key(
        holder,
        holder_generation,
        holder_digest,
        [29; 16],
        1,
        SourceProviderKeyUsageV1::RootMountRecord,
        &root_key,
    )
    .unwrap();
    let signed_root = sign_request(
        SourceProviderMethod::Acquire,
        encode_acquire_request(&root_request),
        root_signer,
        &root_key,
    )
    .unwrap();
    let claims = StorageZfsHoldTransportRequestV1::new(
        1,
        [challenge; 32],
        digest(challenge),
        [30; 16],
        holder,
        digest(24),
        acquisition,
        binding_digest,
        digest(31),
        100,
        150,
        native_catalog,
    )
    .unwrap();
    let provider_key = SigningKey::from_bytes(&[32; 32]);
    let provider_signer = SourceProviderSigningKeyV1::for_signing_key(
        [30; 16],
        1,
        digest(33),
        [34; 16],
        1,
        SourceProviderKeyUsageV1::ProviderOutcome,
        &provider_key,
    )
    .unwrap();
    let request = SignedStorageNativeAcquireRequestV2::sign(
        StorageNativeAcquireRequestV2::new(claims, signed_root).unwrap(),
        provider_signer,
        &provider_key,
    )
    .unwrap();
    let acceptance = StorageNativeAcceptanceV3::new(
        [sequence; 16],
        request.digest(),
        digest(35),
        SourceRootObservationV1::new([36; 16], 37, 38, 39, true, true, true).unwrap(),
        RecursiveTopologyProofV1::new([45; 16], 1, digest(46), 1, 0, 1, 0).unwrap(),
    )
    .unwrap();

    // Only this pure fixture constructs the sealed token. Signatures here do
    // not establish a production current session or live descriptor custody.
    PreparedStorageNativeIssuanceV1 {
        row: NativeIssuanceRowV1 {
            request,
            acceptance,
            retirement: None,
        },
        cut,
    }
}

#[test]
fn live_lookup_retains_exact_acceptance_and_rejects_fresh_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    let original = fixture(1, 2);
    assert_eq!(
        owner.retained_acceptance(&original.row.request).unwrap(),
        None
    );
    owner.accept(&original, &original.cut).unwrap();
    assert_eq!(
        owner.retained_acceptance(&original.row.request).unwrap(),
        Some(original.row.acceptance.clone()),
    );

    let changed = fixture(1, 3);
    assert!(matches!(
        owner.retained_acceptance(&changed.row.request),
        Err(StorageNativeIssuanceErrorV1::Conflict),
    ));
    assert!(matches!(
        owner.check_release(&CatalogPlanV1::ReleaseHold {
            snapshot: original.cut.snapshot.clone(),
            hold_id: original.cut.hold_id,
        }),
        Err(StorageNativeIssuanceErrorV1::HoldInUse),
    ));
}

#[test]
fn native_v3_journal_capacity_includes_topology_before_admission() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let value = prepared.row.encode().unwrap();
    assert_eq!(
        prepared.row.acceptance.to_canonical_bytes().len(),
        STORAGE_NATIVE_ACCEPTANCE_BYTES_V3
    );
    assert_eq!(
        value.len(),
        HEADER_BYTES
            + prepared.row.request.to_canonical_bytes().len()
            + STORAGE_NATIVE_ACCEPTANCE_BYTES_V3,
    );
    assert!(NativeIssuanceRowV1::decode(&value).is_ok());

    let mut too_short = journal_limits();
    too_short.maximum_record_bytes = 7 + prepared.row.key().len() + value.len() - 1;
    let mut owner = open(directory.path(), too_short).unwrap();
    assert!(matches!(
        owner.accept(&prepared, &prepared.cut),
        Err(StorageNativeIssuanceErrorV1::Journal(_))
    ));
    assert!(owner.rows().unwrap().is_empty());
    drop(owner);

    let mut reopened = open(directory.path(), journal_limits()).unwrap();
    assert_eq!(
        reopened.accept(&prepared, &prepared.cut).unwrap(),
        IssuanceCommitOutcomeV1::Recorded
    );
    assert_eq!(
        reopened.retained_acceptance(&prepared.row.request).unwrap(),
        Some(prepared.row.acceptance)
    );
}

#[test]
fn native_v3_journal_refuses_unreleased_legacy_acceptance_without_reinterpretation() {
    let prepared = fixture(1, 42);
    let mut legacy = prepared.row.encode().unwrap();
    let acceptance_start = HEADER_BYTES + prepared.row.request.to_canonical_bytes().len();
    // The old positive acceptance had the same prefix fields but no appended
    // eighty-byte topology. Preserve its old magic/version/width deliberately.
    let legacy_acceptance_bytes = 136_u32;
    legacy[84..88].copy_from_slice(&legacy_acceptance_bytes.to_be_bytes());
    legacy[acceptance_start..acceptance_start + 8].copy_from_slice(b"AOSZNA02");
    legacy[acceptance_start + 8..acceptance_start + 10].copy_from_slice(&2_u16.to_be_bytes());
    legacy.truncate(acceptance_start + legacy_acceptance_bytes as usize);

    assert!(matches!(
        NativeIssuanceRowV1::decode(&legacy),
        Err(StorageNativeIssuanceErrorV1::Noncanonical)
    ));
}

#[test]
fn cold_lookup_does_not_retire_interest_or_replace_original_acceptance() {
    let directory = tempfile::tempdir().unwrap();
    let original = fixture(1, 2);
    {
        let mut owner = open(directory.path(), journal_limits()).unwrap();
        owner.accept(&original, &original.cut).unwrap();
    }
    let mut recovered = open(directory.path(), journal_limits()).unwrap();
    assert_eq!(
        recovered
            .retained_acceptance(&original.row.request)
            .unwrap(),
        Some(original.row.acceptance.clone())
    );
    assert!(matches!(
        recovered.check_release(&CatalogPlanV1::ReleaseHold {
            snapshot: original.cut.snapshot.clone(),
            hold_id: original.cut.hold_id,
        }),
        Err(StorageNativeIssuanceErrorV1::HoldInUse)
    ));
    assert!(recovered.rows().unwrap()[0].retirement.is_none());
}

pub(super) fn open(
    directory: &Path,
    limits: JournalLimits,
) -> Result<StorageNativeIssuanceLedgerV1, StorageNativeIssuanceErrorV1> {
    // tempfile honors the caller's umask; the protected journal requires an
    // explicit private final directory, not merely an unpredictable pathname.
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let identity = fs::symlink_metadata(directory).unwrap();
    let journal =
        Journal::open_protected_at_uid(directory, JOURNAL_FILE, limits, identity.uid())?.0;
    StorageNativeIssuanceLedgerV1::from_journal(
        journal,
        directory,
        NativeIssuanceCustodyV1::UidFixture {
            device: identity.dev(),
            inode: identity.ino(),
        },
    )
}

fn retirement(prepared: &PreparedStorageNativeIssuanceV1) -> PreparedStorageNativeRetirementV1 {
    PreparedStorageNativeRetirementV1 {
        original: prepared.row.clone(),
        provider_terminal_digest: digest(40),
        cleanup_digest: digest(41),
    }
}

#[test]
fn exact_acceptance_and_retirement_replay_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    assert_eq!(
        owner.accept(&prepared, &prepared.cut).unwrap(),
        IssuanceCommitOutcomeV1::Recorded
    );
    drop(owner);

    let mut owner = open(directory.path(), journal_limits()).unwrap();
    assert_eq!(
        owner.accept(&prepared, &prepared.cut).unwrap(),
        IssuanceCommitOutcomeV1::ExactReplay
    );
    assert_eq!(
        owner.retire(&retirement(&prepared)).unwrap(),
        IssuanceCommitOutcomeV1::Recorded
    );
    drop(owner);

    let mut owner = open(directory.path(), journal_limits()).unwrap();
    assert_eq!(
        owner.retire(&retirement(&prepared)).unwrap(),
        IssuanceCommitOutcomeV1::ExactReplay
    );
    assert!(matches!(
        owner.accept(&prepared, &prepared.cut),
        Err(StorageNativeIssuanceErrorV1::Conflict)
    ));
}

#[test]
fn one_acquisition_cannot_equivocate_request_receipt_or_original_descriptor() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    owner.accept(&prepared, &prepared.cut).unwrap();

    let changed_request = fixture(1, 43);
    assert!(matches!(
        owner.accept(&changed_request, &changed_request.cut),
        Err(StorageNativeIssuanceErrorV1::Conflict)
    ));
    for (receipt, descriptor) in [
        (digest(50), prepared.row.acceptance.descriptor().clone()),
        (
            digest(35),
            SourceRootObservationV1::new([36; 16], 37, 38, 49, true, true, true).unwrap(),
        ),
    ] {
        let acceptance = StorageNativeAcceptanceV3::new(
            [1; 16],
            prepared.row.request.digest(),
            receipt,
            descriptor,
            prepared.row.acceptance.topology().clone(),
        )
        .unwrap();
        let changed = PreparedStorageNativeIssuanceV1 {
            row: NativeIssuanceRowV1 {
                acceptance,
                ..prepared.row.clone()
            },
            cut: prepared.cut.clone(),
        };
        assert!(matches!(
            owner.accept(&changed, &changed.cut),
            Err(StorageNativeIssuanceErrorV1::Conflict)
        ));
    }
    let mut changed_signature = prepared.row.request.to_canonical_bytes();
    let last = changed_signature.len() - 1;
    changed_signature[last] ^= 1;
    let changed = PreparedStorageNativeIssuanceV1 {
        row: NativeIssuanceRowV1 {
            request: SignedStorageNativeAcquireRequestV2::from_canonical_bytes(&changed_signature)
                .unwrap(),
            ..prepared.row.clone()
        },
        cut: prepared.cut.clone(),
    };
    assert!(owner.accept(&changed, &changed.cut).is_err());
}

#[test]
fn challenge_attempt_and_issuance_id_are_not_recycled_between_acquisitions() {
    let directory = tempfile::tempdir().unwrap();
    let first = fixture(1, 42);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    owner.accept(&first, &first.cut).unwrap();
    owner.retire(&retirement(&first)).unwrap();

    let reused_challenge = fixture(2, 42);
    assert!(matches!(
        owner.accept(&reused_challenge, &reused_challenge.cut),
        Err(StorageNativeIssuanceErrorV1::Conflict)
    ));
    let mut reused_issuance = fixture(2, 43);
    reused_issuance.row.acceptance = StorageNativeAcceptanceV3::new(
        [1; 16],
        reused_issuance.row.request.digest(),
        digest(35),
        first.row.acceptance.descriptor().clone(),
        first.row.acceptance.topology().clone(),
    )
    .unwrap();
    assert!(matches!(
        owner.accept(&reused_issuance, &reused_issuance.cut),
        Err(StorageNativeIssuanceErrorV1::Conflict)
    ));
}

#[test]
fn stale_final_cut_and_reheld_native_lineage_never_accept_even_exact_replay() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    let mut stale = prepared.cut.clone();
    stale.authority_sequence += 1;
    assert!(matches!(
        owner.accept(&prepared, &stale),
        Err(StorageNativeIssuanceErrorV1::StaleHold)
    ));
    assert!(owner.rows().unwrap().is_empty());

    owner.accept(&prepared, &prepared.cut).unwrap();
    assert!(matches!(
        owner.accept(&prepared, &stale),
        Err(StorageNativeIssuanceErrorV1::StaleHold)
    ));
    let mut reheld = prepared.cut.clone();
    reheld.hold_generation += 1;
    assert!(matches!(
        validate_hold_cut(&prepared.row, &reheld),
        Err(StorageNativeIssuanceErrorV1::StaleHold)
    ));
    reheld = prepared.cut.clone();
    reheld.active_hold_digest = digest(52);
    assert!(validate_hold_cut(&prepared.row, &reheld).is_err());
}

#[test]
fn release_is_excluded_until_every_exact_consumer_retires() {
    let directory = tempfile::tempdir().unwrap();
    let first = fixture(1, 42);
    let second = fixture(2, 43);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    owner.accept(&first, &first.cut).unwrap();
    owner.accept(&second, &second.cut).unwrap();
    let release = CatalogPlanV1::ReleaseHold {
        snapshot: first.cut.snapshot.clone(),
        hold_id: first.cut.hold_id,
    };
    assert!(matches!(
        owner.check_release(&release),
        Err(StorageNativeIssuanceErrorV1::HoldInUse)
    ));
    owner.retire(&retirement(&first)).unwrap();
    assert!(owner.check_release(&release).is_err());
    owner.retire(&retirement(&second)).unwrap();
    owner.check_release(&release).unwrap();
}

#[test]
fn handle_and_name_aliases_do_not_bypass_physical_release_exclusion() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    owner.accept(&prepared, &prepared.cut).unwrap();
    let original = prepared.cut.snapshot.dataset();
    let alias = ResolvedDataset::from_catalog(
        original.root().clone(),
        "tank/aos/renamed",
        original.guid(),
        [99; 32],
        original.domains(),
    )
    .unwrap();
    let snapshot =
        ResolvedSnapshot::from_catalog(alias, "alias", prepared.cut.snapshot.guid(), [98; 32])
            .unwrap();
    assert!(
        owner
            .check_release(&CatalogPlanV1::ReleaseHold {
                snapshot,
                hold_id: prepared.cut.hold_id
            })
            .is_err()
    );
    owner
        .check_release(&CatalogPlanV1::ReleaseHold {
            snapshot: prepared.cut.snapshot.clone(),
            hold_id: HoldId::from_bytes([97; 16]).unwrap(),
        })
        .unwrap();
}

#[test]
fn later_admission_cannot_consume_earlier_consumers_retirement_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let mut limits = journal_limits();
    limits.maximum_transactions = 3;
    let first = fixture(1, 42);
    let second = fixture(2, 43);
    let mut owner = open(directory.path(), limits).unwrap();
    owner.accept(&first, &first.cut).unwrap();
    assert!(owner.accept(&second, &second.cut).is_err());
    assert_eq!(owner.rows().unwrap().len(), 1);
    owner.retire(&retirement(&first)).unwrap();
    drop(owner);
    assert_eq!(
        open(directory.path(), limits)
            .unwrap()
            .rows()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn exact_transaction_boundary_preserves_retirement_in_either_order() {
    for reverse in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut limits = journal_limits();
        limits.maximum_transactions = 4;
        let first = fixture(1, 42);
        let second = fixture(2, 43);
        let mut owner = open(directory.path(), limits).unwrap();
        owner.accept(&first, &first.cut).unwrap();
        owner.accept(&second, &second.cut).unwrap();
        let order = if reverse {
            [&second, &first]
        } else {
            [&first, &second]
        };
        for prepared in order {
            owner.retire(&retirement(prepared)).unwrap();
        }
        drop(owner);
        assert!(
            open(directory.path(), limits)
                .unwrap()
                .rows()
                .unwrap()
                .iter()
                .all(|row| row.retirement.is_some())
        );
    }
}

#[test]
fn materialized_limit_and_reopen_preserve_the_last_cleanup_slot() {
    let directory = tempfile::tempdir().unwrap();
    let mut limits = journal_limits();
    limits.maximum_materialized_records = 1;
    let first = fixture(1, 42);
    let second = fixture(2, 43);
    let mut owner = open(directory.path(), limits).unwrap();
    owner.accept(&first, &first.cut).unwrap();
    assert!(owner.accept(&second, &second.cut).is_err());
    drop(owner);

    let mut insufficient = limits;
    insufficient.maximum_transactions = 1;
    assert!(open(directory.path(), insufficient).is_err());
    let mut owner = open(directory.path(), limits).unwrap();
    owner.retire(&retirement(&first)).unwrap();
    assert_eq!(owner.rows().unwrap().len(), 1);
}

#[test]
fn append_byte_budget_reserves_the_full_retirement_before_first_acceptance() {
    let measure = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(measure.path(), journal_limits()).unwrap();
    owner.accept(&prepared, &prepared.cut).unwrap();
    let one_transaction_bytes = fs::metadata(measure.path().join(JOURNAL_FILE))
        .unwrap()
        .len();
    drop(owner);

    let directory = tempfile::tempdir().unwrap();
    let mut limits = journal_limits();
    limits.maximum_journal_bytes = one_transaction_bytes * 2 - 1;
    let mut owner = open(directory.path(), limits).unwrap();
    assert!(owner.accept(&prepared, &prepared.cut).is_err());
    assert!(owner.rows().unwrap().is_empty());
}

#[test]
fn conflicting_or_sentinel_cleanup_cannot_retire_original_interest() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    owner.accept(&prepared, &prepared.cut).unwrap();
    let mut wrong = retirement(&prepared);
    wrong.original.acceptance = StorageNativeAcceptanceV3::new(
        [1; 16],
        prepared.row.request.digest(),
        digest(55),
        prepared.row.acceptance.descriptor().clone(),
        prepared.row.acceptance.topology().clone(),
    )
    .unwrap();
    assert!(owner.retire(&wrong).is_err());
    let mut sentinel = retirement(&prepared);
    sentinel.cleanup_digest = ObjectDigest::from_bytes([0; 32]);
    assert!(owner.retire(&sentinel).is_err());
    assert!(owner.rows().unwrap()[0].retirement.is_none());

    owner.retire(&retirement(&prepared)).unwrap();
    let mut changed = retirement(&prepared);
    changed.provider_terminal_digest = digest(56);
    assert!(matches!(
        owner.retire(&changed),
        Err(StorageNativeIssuanceErrorV1::Conflict)
    ));
}

#[test]
fn crash_tail_reopens_only_exact_durable_active_interest() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(directory.path(), journal_limits()).unwrap();
    owner.accept(&prepared, &prepared.cut).unwrap();
    drop(owner);
    let path = directory.path().join(JOURNAL_FILE);
    let durable_length = fs::metadata(&path).unwrap().len();
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0xA0, 0x53, 0x17]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let mut owner = open(directory.path(), journal_limits()).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), durable_length);
    assert_eq!(
        owner.accept(&prepared, &prepared.cut).unwrap(),
        IssuanceCommitOutcomeV1::ExactReplay
    );
    assert!(
        owner
            .check_release(&CatalogPlanV1::ReleaseHold {
                snapshot: prepared.cut.snapshot.clone(),
                hold_id: prepared.cut.hold_id,
            })
            .is_err()
    );
}

#[test]
fn replay_rejects_relocated_foreign_or_malformed_materialized_rows() {
    for kind in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let prepared = fixture(1, 42);
        let mut journal = Journal::open_protected_at_uid(
            directory.path(),
            JOURNAL_FILE,
            journal_limits(),
            fs::metadata(directory.path()).unwrap().uid(),
        )
        .unwrap()
        .0;
        let key = if kind == 0 {
            [99; 48]
        } else {
            prepared.row.key()
        };
        let namespace = if kind == 1 {
            RecordNamespace::Effect
        } else {
            RecordNamespace::AuthorityPublication
        };
        let mut value = prepared.row.encode().unwrap();
        if kind == 2 {
            value[10] = 1;
        }
        journal
            .commit(
                &JournalTransaction::new(
                    [99; 16],
                    vec![JournalRecord::put(namespace, key.to_vec(), value)],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        assert!(open(directory.path(), journal_limits()).is_err());
    }
}

#[test]
fn named_journal_or_lock_replacement_cannot_authorize_release_or_cleanup() {
    for replace_lock in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let prepared = fixture(1, 42);
        let mut owner = open(directory.path(), journal_limits()).unwrap();
        owner.accept(&prepared, &prepared.cut).unwrap();
        let name = if replace_lock {
            format!("{JOURNAL_FILE}.lock")
        } else {
            JOURNAL_FILE.to_owned()
        };
        let original = directory.path().join(&name);
        let archived = directory.path().join(format!("{name}.orphan"));
        fs::rename(&original, &archived).unwrap();
        fs::copy(&archived, &original).unwrap();

        assert!(
            owner
                .check_release(&CatalogPlanV1::ReleaseHold {
                    snapshot: prepared.cut.snapshot.clone(),
                    hold_id: prepared.cut.hold_id,
                })
                .is_err()
        );
        assert!(owner.accept(&prepared, &prepared.cut).is_err());
        assert!(owner.retire(&retirement(&prepared)).is_err());
    }
}

#[test]
fn replaced_state_directory_cannot_leave_an_orphaned_writer_authoritative() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("state");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = fixture(1, 42);
    let mut owner = open(&directory, journal_limits()).unwrap();
    owner.accept(&prepared, &prepared.cut).unwrap();
    fs::rename(&directory, parent.path().join("orphan")).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

    assert!(
        owner
            .check_release(&CatalogPlanV1::ReleaseHold {
                snapshot: prepared.cut.snapshot.clone(),
                hold_id: prepared.cut.hold_id,
            })
            .is_err()
    );
    assert!(owner.retire(&retirement(&prepared)).is_err());
}
