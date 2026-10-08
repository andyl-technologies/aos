//! Original archive service admission and refusal before namespace access.

use super::*;
use crate::campaign_store_composition::CampaignArchiveHostOperation;

#[test]
fn archive_resource_refusal_stays_inline_before_namespace_access() {
    let mut authored = config();
    authored.resources.file_descriptors = 35;

    let refused = CampaignArchiveHostOperation::start_with_quota(
        HostOperationClass::Transfer,
        authored.budgets,
        Duration::from_secs(60),
        authored.resources,
    );

    assert!(matches!(
        refused,
        Err(ProviderServiceAdmissionError::Store(StoreError::Quota))
    ));
}

#[test]
fn archive_cancellation_keeps_same_original_before_opening_project() {
    let authored = config();
    let archive = CampaignArchiveHostOperation::start_with_quota(
        HostOperationClass::Transfer,
        authored.budgets,
        Duration::from_secs(60),
        authored.resources,
    )
    .unwrap_or_else(|error| panic!("original archive admission: {error}"));
    let supervisor = archive.supervisor();
    let origin = supervisor
        .outer_cap_binding()
        .unwrap_or_else(|error| panic!("original cap: {error}"));
    let statuses = supervisor
        .operation_statuses()
        .unwrap_or_else(|error| panic!("original operation roster: {error}"));
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.class == HostOperationClass::Transfer)
            .count(),
        1
    );
    archive
        .boundary()
        .unwrap_or_else(|error| panic!("original archive boundary: {error}"));
    assert_eq!(
        supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("retained original cap: {error}")),
        origin
    );

    supervisor
        .cancel()
        .unwrap_or_else(|error| panic!("original cancellation: {error}"));
    let refused =
        archive.bind_archive_namespace(Path::new("/aos-archive-test-no-such-root"), 1, 4096, 16);

    assert!(matches!(
        refused,
        Err(ProviderServiceAdmissionError::Supervision(_))
    ));
    eprintln!(
        "archive_owner={} namespace_owner={} construction={} admission={}",
        std::mem::size_of::<CampaignArchiveHostOperation>(),
        std::mem::size_of::<CampaignArchiveNamespace>(),
        std::mem::size_of::<QuotaServiceConstruction>(),
        std::mem::size_of::<QuotaServiceAdmission>(),
    );
}

#[test]
fn plain_archive_lifetime_never_creates_a_quota_service_implicitly() {
    let archive =
        CampaignArchiveHostOperation::start(HostOperationClass::Transfer, Duration::from_secs(60))
            .unwrap_or_else(|error| panic!("metadata archive lifetime: {error}"));

    let refused =
        archive.bind_archive_namespace(Path::new("/aos-archive-test-no-such-root"), 1, 4096, 16);

    assert!(matches!(
        refused,
        Err(ProviderServiceAdmissionError::Store(
            StoreError::Unsupported {
                capability: "admitted-archive-namespace"
            }
        ))
    ));
}
