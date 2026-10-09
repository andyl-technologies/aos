//! Classifies one asserted GC mark publication continuation under its original.
//!
//! The first flush actually publishes immutable nodes and returns a typed
//! refusal. The same retained page then finishes once under the same healthy
//! original; a failed test is never rerun. Exact body and fixture obligations
//! keep additional attempts and changed custody visible to flaky-test scanning.

use super::{Companion, Contract};

const CONTINUATION: &str = r#"fn partial_checked_publication_does_not_install_a_mark_root_and_can_retry() {
    let mut fixture = super::super::tests::operation::ComponentGcOperation::new();
    let source_operation = fixture.context();
    let original = source_operation.original();
    let backend = counted(source_operation.marks());
    let mut marks = Reachability::with_backend(backend.clone(), original).unwrap();
    let prior = marks.root;
    let mut boundary = || source_operation.check();
    let operation =
        CampaignGcOperationContext::new(backend.clone(), original, &mut boundary).unwrap();
    let mut pending = PendingMarks::new(&operation).unwrap();
    for index in 0..63 {
        pending.insert(&mut marks, page(index), &operation).unwrap();
    }
    backend
        .refuse_after_publication
        .store(true, Ordering::Relaxed);

    let error = pending.flush(&mut marks, &operation).unwrap_err();

    assert!(
        matches!(&error,
            StoreError::StreamIo { source, .. }
            if matches!(source.get_ref().and_then(|source| source.downcast_ref::<crucible_campaign::CampaignStoreError>()),
                Some(crucible_campaign::CampaignStoreError::Store(StoreError::Unsupported {
                    capability: "actual-mark-publication-then-refusal"
                })))
        ),
        "actual typed first publication refusal: {error:?}"
    );
    assert_eq!(marks.root, prior);
    assert!(backend.objects.load(Ordering::Relaxed) > 0);
    assert!(!marks.contains(&page(0)).unwrap());
    original.verify_live().unwrap();
    backend
        .refuse_after_publication
        .store(false, Ordering::Relaxed);
    pending.flush(&mut marks, &operation).unwrap();
    assert_eq!(marks.len(), 63);
    assert!(marks.contains(&page(0)).unwrap());
}"#;

const PUBLISHED_REFUSAL: &str = r#"fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        self.publications.fetch_add(1, Ordering::Relaxed);
        self.objects
            .fetch_add(objects.len() as u64, Ordering::Relaxed);
        let receipt = self
            .inner
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        if self.refuse_after_publication.load(Ordering::Relaxed) {
            return Err(StoreError::Unsupported {
                capability: "actual-mark-publication-then-refusal",
            });
        }
        Ok(receipt)
    }"#;

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/campaign_gc/reachability/batched_tests",
    required: &[CONTINUATION, PUBLISHED_REFUSAL],
    // Only this one declaration contains the reviewed lexical token. Its full
    // body pins both flushes, their order, typed refusal, retained root and page,
    // original health check and authenticated completion assertions.
    expressions: &[(
        "fn partial_checked_publication_does_not_install_a_mark_root_and_can_retry()",
        1,
    )],
    companions: &[Companion {
        path: "crates/crucible-daemon/src/campaign_gc/tests/operation.rs",
        required: &[
            r#"let decoding = DecodeBudget::for_store(Arc::clone(&resources))"#,
            r#"HostOperationBudgets {
                classes: [HostOperationBudget::finite(Duration::from_secs(300));
                    HOST_OPERATION_CLASS_COUNT],
            },
            Some(Duration::from_secs(300)),"#,
            "let original = supervisor.begin(HostOperationClass::Transfer)",
            r#"let marks = SqliteBlobBackend::open_with_physical_quota(
                "component-gc-marks", scratch.path(), Arc::clone(&resources),
                8 * 1024 * 1024, sqlite,
                &crucible_cas::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process"),
            )"#,
            r#"boundary: Box::new(move || {
                original.wait_slice().map(|_| ()).map_err(supervision_error)
            })"#,
            r#"CampaignGcOperationContext::new(
                Arc::clone(&self.marks), &self.decoding, self.boundary.as_mut(),
            )"#,
        ],
        counts: &[
            ("HostOperationSupervisor::new(", 1),
            (".begin(HostOperationClass::Transfer)", 1),
            ("DecodeBudget::for_store(", 1),
        ],
    }],
}];

#[cfg(test)]
mod tests {
    use super::super::{mask_with_companions, pattern, read_companions};
    use super::*;

    fn scrub(source: &str) -> String {
        super::super::super::super::scrub_comments_and_strings(source)
    }

    fn rejected(source: &str, companions: &[String]) -> bool {
        let code = mask_with_companions(&CONTRACTS[0], &scrub(source), companions);
        super::super::super::super::flaky_escape_failures("unreviewed", "unreviewed", &code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    }

    #[test]
    fn gc_mark_continuation_requires_exact_outcome_and_two_publication_attempts()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let root = super::super::super::super::super::workspace_root();
        let source = std::fs::read_to_string(
            root.join("crates/crucible-daemon")
                .join(format!("{}.rs", contract.target)),
        )?;
        let companions = read_companions(contract)?;
        assert!(!rejected(&source, &companions));
        let compact = pattern(&source);
        for (before, after) in [
            (
                "pending.flush(&mut marks, &operation).unwrap_err();",
                "pending.flush(&mut marks, &operation).unwrap();",
            ),
            ("assert_eq!(marks.root, prior);", "removed_prior_root();"),
            (
                "assert!(!marks.contains(&page(0)).unwrap());",
                "removed_absence_authentication();",
            ),
            (
                "original.verify_live().unwrap();",
                "foreign.verify_live().unwrap();",
            ),
            (
                "pending.flush(&mut marks, &operation).unwrap();",
                "loop { pending.flush(&mut marks, &operation).unwrap(); }",
            ),
            (
                "assert_eq!(marks.len(), 63);",
                "removed_completion_count();",
            ),
            (
                "assert!(marks.contains(&page(0)).unwrap());",
                "removed_completion_authentication();",
            ),
            (
                "source.downcast_ref::<crucible_campaign::CampaignStoreError>()",
                "source.downcast_ref::<DifferentError>()",
            ),
            (
                "let original = source_operation.original();",
                "let original = foreign.original();",
            ),
            (
                "self.inner.put_many_if_absent_with_boundary(original, objects, boundary)?",
                "self.inner.put_many_if_absent(objects)?",
            ),
            (
                "let receipt = self.inner.put_many_if_absent_with_boundary(original, objects, boundary)?;",
                "let extra = self.inner.put_many_if_absent(objects)?; let receipt = self.inner.put_many_if_absent_with_boundary(original, objects, boundary)?;",
            ),
        ] {
            let before = pattern(before);
            assert!(
                compact.contains(&before),
                "missing mutation preimage: {before}"
            );
            let continuation = pattern(CONTINUATION);
            let changed = if continuation.contains(&before) {
                compact.replacen(
                    &continuation,
                    &continuation.replacen(&before, &pattern(after), 1),
                    1,
                )
            } else {
                compact.replacen(&before, &pattern(after), 1)
            };
            assert!(
                rejected(&changed, &companions),
                "changed mark continuation admitted: {before}"
            );
        }
        for addition in [
            "fn conceal() { retry(); }",
            "fn conceal() { retry!(); }",
            "fn conceal() { retry_failed_test(); }",
            "fn conceal() { partial_checked_publication_does_not_install_a_mark_root_and_can_retry(); }",
            "fn conceal() { loop { retry_failed_test(); } }",
            "fn partial_checked_publication_does_not_install_a_mark_root_and_can_retry() {}",
        ] {
            assert!(
                rejected(&format!("{source}\n{addition}"), &companions),
                "additional attempt admitted: {addition}"
            );
        }
        let foreign = super::super::mask("foreign", contract.target, &scrub(&source));
        assert!(
            super::super::super::super::flaky_escape_failures("unreviewed", "unreviewed", &foreign)
                .iter()
                .any(|finding| finding.contains("`retry`"))
        );
        let foreign = super::super::mask(contract.package, "foreign", &scrub(&source));
        assert!(
            super::super::super::super::flaky_escape_failures("unreviewed", "unreviewed", &foreign)
                .iter()
                .any(|finding| finding.contains("`retry`"))
        );
        Ok(())
    }

    #[test]
    fn gc_mark_continuation_requires_one_original_fixture_clock_and_catalog()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let root = super::super::super::super::super::workspace_root();
        let source = std::fs::read_to_string(
            root.join("crates/crucible-daemon")
                .join(format!("{}.rs", contract.target)),
        )?;
        let companions = read_companions(contract)?;
        assert!(rejected(&source, &[]));
        for (before, after) in [
            ("Duration::from_secs(300)", "Duration::from_secs(301)"),
            (
                "Arc::clone(&self.marks), &self.decoding, self.boundary.as_mut()",
                "Arc::clone(&self.marks), &foreign.decoding, foreign.boundary.as_mut()",
            ),
            (
                "DecodeBudget::for_store(Arc::clone(&resources))",
                "DecodeBudget::for_store(Arc::clone(&foreign_resources))",
            ),
            ("8 * 1024 * 1024", "9 * 1024 * 1024"),
            ("original.wait_slice()", "foreign.wait_slice()"),
        ] {
            let compact = pattern(&companions[0]);
            let before = pattern(before);
            assert!(
                compact.contains(&before),
                "missing fixture preimage: {before}"
            );
            let changed = vec![compact.replacen(&before, &pattern(after), 1)];
            assert!(
                rejected(&source, &changed),
                "changed original fixture admitted: {before}"
            );
        }
        Ok(())
    }
}
