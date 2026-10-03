//! UNRUN sealed prospective DATA and failure boundaries, not genuine owner GO.

use super::*;

fn transaction(order: bool) -> JournalTransaction {
    let mut records = vec![
        super::super::super::JournalRecord::put(RecordNamespace::SourceProviderAuthority,
            vec![1], vec![2]),
        super::super::super::JournalRecord::put(RecordNamespace::SourceProviderAuthority,
            vec![3], vec![4]),
    ];
    if order { records.reverse(); }
    JournalTransaction::new([1; 16], records).unwrap()
}

#[test]
fn ordered_subject_digest_does_not_authorize_reordered_owner_operations() {
    let original = transaction(false);
    let reordered = transaction(true);

    assert_ne!(authority_preflight_digest(&[original]), authority_preflight_digest(&[reordered]));
}

#[test]
fn prospective_subject_reports_no_physical_readback_or_currentness_conversion() {
    let transaction = transaction(false);
    let subject = SourceOriginalAppendSubjectV5 {
        identity: (2, 3), transaction: *transaction.id(),
        digest: authority_preflight_digest(std::slice::from_ref(&transaction)),
        begin_sequence: 4, commit_sequence: 7, begin_offset: 8,
    };

    assert_eq!(subject.file_identity(), (2, 3));
    assert_eq!(subject.prefix(), (4, 8));
    assert_eq!(subject.frame_sequences(), (4, 7));
    assert_eq!(subject.transaction().0, *transaction.id());
    // A prospective DTO is not a ProtectedReadback/JournalAuthority constructor.
}
