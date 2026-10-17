//! Streamed selection resolution, dependency sharing, and resident limits.

use super::*;

/// Publishes one workload declaration over a boolean domain of one semantic version.
fn publish_declaration(
    repository: &CampaignRepository,
    name: &str,
    semantic_version: u32,
) -> (SelectableDeclaration, ChoiceDomain) {
    let domain =
        ChoiceDomain::Boolean(BooleanDomain::new(semantic_version).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        name,
        ChoiceSource::Workload {
            producer: name.to_owned(),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    (declaration, domain)
}

/// Publishes one default selection of a fresh opportunity and returns its ID.
fn publish_selection(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    declaration: &SelectableDeclaration,
    domain: &ChoiceDomain,
    ordinal: u32,
) -> SelectionId {
    let material = ordinal.to_le_bytes();
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        declaration,
        domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test.selection-resolver", &material),
            producer: CampaignHash::derive("test", declaration.name().as_bytes()),
        },
        format!("selection-{ordinal}"),
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let selection = Selection::new(
        &opportunity,
        domain,
        ChoiceValue::Boolean(false),
        crate::SelectionOrigin::Default,
    )
    .expect("selection");
    repository
        .publish_selection(&selection)
        .expect("publish selection")
}

/// Returns the stored canonical bytes of one record.
fn stored_bytes(blobs: &MemoryBlobBackend, id: ContentId) -> usize {
    let length = blobs
        .read(id, None)
        .expect("stored record")
        .logical_length();
    usize::try_from(length).expect("record length")
}

/// Returns the canonical bytes of every record one selection resolves.
fn selection_closure_bytes(
    repository: &CampaignRepository,
    blobs: &MemoryBlobBackend,
    id: SelectionId,
) -> usize {
    let resolved = repository.resolve_selection(id).expect("resolve selection");
    let opportunity = resolved.opportunity();
    [
        id.content_id(),
        opportunity.id().expect("opportunity id").content_id(),
        opportunity.declaration().content_id(),
        opportunity.domain().content_id(),
    ]
    .into_iter()
    .map(|record| stored_bytes(blobs, record))
    .sum()
}

#[test]
fn selection_resolver_shares_dependencies_across_streamed_selections() {
    let (repository, lineage, _, _) = counted_fixture();
    let (declaration, domain) = publish_declaration(&repository, "product.test.selection-batch", 1);
    let ids = (0..256)
        .map(|ordinal| publish_selection(&repository, &lineage, &declaration, &domain, ordinal))
        .collect::<Vec<_>>();

    let mut resolver = repository.selection_resolver();
    let first = resolver.resolve(ids[0]).expect("resolve first selection");
    for id in &ids {
        let resolved = resolver.resolve(*id).expect("resolve selection");

        assert_eq!(resolved.selection().id().expect("selection id"), *id);
        assert!(std::ptr::eq(resolved.domain(), first.domain()));
        assert!(std::ptr::eq(resolved.declaration(), first.declaration()));
    }
}

#[test]
fn selection_resolver_streams_past_the_former_batch_record_limit() {
    let (repository, lineage, _, _) = counted_fixture();
    let (declaration, domain) = publish_declaration(&repository, "product.test.selection-run", 1);
    let id = publish_selection(&repository, &lineage, &declaration, &domain, 0);
    // The batch resolver rejected more than 4,096 identities in one call.
    let repeated = vec![id; 4_097];

    let mut visited = 0usize;
    CampaignExecutorStore::new(Arc::new(repository))
        .for_each_resolved_selection(&repeated, |resolved| {
            assert_eq!(resolved.selection().id()?, id);
            visited += 1;
            Ok::<_, CampaignRepositoryError>(())
        })
        .expect("stream repeated selection");

    assert_eq!(visited, repeated.len());
}

#[test]
fn distinct_selection_visit_rejects_repetition_before_reading_records() {
    let (repository, lineage, _, _) = counted_fixture();
    let (declaration, domain) =
        publish_declaration(&repository, "product.test.selection-distinct", 1);
    let id = publish_selection(&repository, &lineage, &declaration, &domain, 0);

    let mut visited = 0usize;
    let result = repository.for_each_resolved_distinct_selection(&[id, id], |_| {
        visited += 1;
        Ok::<_, CampaignRepositoryError>(())
    });

    assert!(matches!(
        result,
        Err(CampaignRepositoryError::Integrity {
            reason: "configuration-selection-identity-repeated"
        })
    ));
    assert_eq!(visited, 0);
}

#[test]
fn resident_limit_rejects_an_oversized_record_before_opening_it() {
    let (repository, lineage, _, blobs) = counted_fixture();
    let (declaration, domain) = publish_declaration(&repository, "product.test.selection-limit", 1);
    let id = publish_selection(&repository, &lineage, &declaration, &domain, 0);
    let target_logical_length = blobs
        .read(id.content_id(), None)
        .expect("selection record")
        .logical_length();
    let open_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bounded_repository = CampaignRepository::new(
        Arc::new(FailOnOpenBlobBackend {
            inner: blobs,
            target: id.content_id(),
            target_logical_length,
            open_calls: open_calls.clone(),
        }),
        repository.refs.clone(),
    );
    let undersized_limit = usize::try_from(target_logical_length)
        .expect("selection record length")
        .checked_sub(1)
        .expect("nonempty selection record");

    let result = SelectionResolver::within(&bounded_repository, undersized_limit).resolve(id);

    assert!(matches!(
        result,
        Err(CampaignRepositoryError::SelectionResolutionBudgetExceeded {
            maximum_canonical_bytes
        }) if maximum_canonical_bytes == undersized_limit
    ));
    assert_eq!(open_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn resident_limit_empties_caches_instead_of_failing_a_fitting_selection() {
    let (repository, lineage, _, blobs) = counted_fixture();
    let (first_declaration, first_domain) =
        publish_declaration(&repository, "product.test.selection-first", 1);
    let (second_declaration, second_domain) =
        publish_declaration(&repository, "product.test.selection-second", 2);
    let first = publish_selection(&repository, &lineage, &first_declaration, &first_domain, 0);
    let second = publish_selection(
        &repository,
        &lineage,
        &second_declaration,
        &second_domain,
        1,
    );
    // Each selection fits alone, but not beside the other's cached records.
    let limit = selection_closure_bytes(&repository, &blobs, first).max(selection_closure_bytes(
        &repository,
        &blobs,
        second,
    ));

    let mut resolver = SelectionResolver::within(&repository, limit);
    resolver.resolve(first).expect("resolve first selection");
    let resolved = resolver
        .resolve(second)
        .expect("resolve second selection after emptying caches");
    assert_eq!(resolved.selection().id().expect("selection id"), second);

    let mut undersized = SelectionResolver::within(&repository, limit - 1);
    let larger = if selection_closure_bytes(&repository, &blobs, first) == limit {
        first
    } else {
        second
    };
    assert!(matches!(
        undersized.resolve(larger),
        Err(CampaignRepositoryError::SelectionResolutionBudgetExceeded { .. })
    ));
}
