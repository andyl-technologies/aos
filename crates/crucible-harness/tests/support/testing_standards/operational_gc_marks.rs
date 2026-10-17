//! Checks terminal sorted-run marking against its exact original fixture.
//!
//! Publication refusal retains the prior mark root, accepted heads and page.
//! A second insert performs no publication; complete-tail refusal remains sticky.
//! These contracts assert current obligations and grant no retry exemption.

use super::Companion;

const CARRY_REFUSAL: &str = r#"fn failed_run_publication_retains_page_heads_and_original_mark_root() {
    let mut fixture = ComponentGcOperation::new();
    let source_operation = fixture.context();
    let backend = counted(source_operation.marks());
    let mut boundary = || source_operation.check();
    let operation = CampaignGcOperationContext::new(
        backend.clone(),
        source_operation.original(),
        &mut boundary,
    )
    .unwrap();
    let marks = Reachability::with_operation(&operation).unwrap();
    let prior = marks.root;
    let mut sorter = SortOwner::new(&operation).unwrap();
    for index in 0..(3 * PAGE) as u64 {
        sorter.insert(page(index)).unwrap();
    }
    let accepted = sorter.levels;
    for index in (3 * PAGE) as u64..(4 * PAGE - 1) as u64 {
        sorter.insert(page(index)).unwrap();
    }
    // Accept the new page and the first two-page merge, then refuse the
    // final carry after its real publication. Both old ranks must survive.
    let before_carry = backend.publications.load(Ordering::Relaxed);
    backend
        .refuse_on_publication
        .store(before_carry + 3, Ordering::Relaxed);

    let error = sorter.insert(page((4 * PAGE - 1) as u64)).unwrap_err();
    assert_eq!(
        backend.publications.load(Ordering::Relaxed),
        before_carry + 3
    );
    assert!(matches!(
        error.original_failure(),
        StoreError::Unsupported {
            capability: "actual-mark-publication-then-refusal"
        }
    ));
    assert_eq!(marks.root, prior);
    assert_eq!(sorter.page.len(), PAGE);
    assert!(
        sorter
            .levels
            .iter()
            .zip(accepted)
            .all(|(actual, expected)| {
                actual.map(|run| run.node) == expected.map(|run| run.node)
            })
    );
    assert!(backend.objects.load(Ordering::Relaxed) > 0);
    let before = backend.publications.load(Ordering::Relaxed);
    assert!(matches!(
        sorter.insert(page(999_999)),
        Err(StoreError::Unsupported {
            capability: "failed-GC-run-owner"
        })
    ));
    assert_eq!(sorter.page.len(), PAGE);
    assert_eq!(backend.publications.load(Ordering::Relaxed), before);
    operation.original().verify_live().unwrap();
}"#;

const COMPLETE_TAIL: &str = r#"fn complete_run_tail_and_fallible_builder_tail_keep_initiating_cause() {
    let mut fixture = ComponentGcOperation::new();
    let source_operation = fixture.context();
    let refuse = AtomicBool::new(false);
    let mut boundary = || {
        if refuse.load(Ordering::Relaxed) {
            Err(StoreError::Unsupported {
                capability: "GC-tail-original-refusal",
            })
        } else {
            source_operation.check()
        }
    };
    let operation = CampaignGcOperationContext::new(
        source_operation.marks(),
        source_operation.original(),
        &mut boundary,
    )
    .unwrap();
    let backend = operation.marks();
    let mut writer = RunWriter::new(backend.as_ref(), &operation).unwrap();
    let entry = (mark_key(page(0)), page(0));
    writer.push(entry).unwrap();
    let run = writer.finish().unwrap().unwrap();
    let mut cursor = Cursor::new(run, backend.as_ref(), &operation).unwrap();
    assert_eq!(cursor.next_entry().unwrap(), Some(entry));
    refuse.store(true, Ordering::Relaxed);
    assert!(matches!(
        cursor.next_entry(),
        Err(StoreError::Unsupported {
            capability: "GC-tail-original-refusal"
        })
    ));
    assert!(!cursor.complete);
    refuse.store(false, Ordering::Relaxed);
    assert!(cursor.next_entry().is_err());

    let marks = Reachability::with_operation(&operation).unwrap();
    let account = mark_account(operation.original()).unwrap();
    let input = [
        Ok(entry),
        Err(StoreError::Unsupported {
            capability: "authenticated-input-tail-failure",
        }),
    ];
    assert!(matches!(
        marks
            .map
            .build_from_sorted_with_boundary(input, &account, &mut || operation.check(),),
        Err(crucible_campaign::CampaignStoreError::Store(
            StoreError::Unsupported {
                capability: "authenticated-input-tail-failure"
            }
        ))
    ));
    assert_eq!(marks.len(), 0);
}"#;

const PUBLISHED_REFUSAL: &str = r#"fn put_many_if_absent_with_boundary(
        &self,
        original: &DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        let ordinal = self.publications.fetch_add(1, Ordering::Relaxed) + 1;
        self.objects
            .fetch_add(objects.len() as u64, Ordering::Relaxed);
        let receipt = self
            .inner
            .put_many_if_absent_with_boundary(original, objects, boundary)?;
        if self.refuse_after_publication.load(Ordering::Relaxed)
            || self.refuse_on_publication.load(Ordering::Relaxed) == ordinal
        {
            return Err(StoreError::Unsupported {
                capability: "actual-mark-publication-then-refusal",
            });
        }
        Ok(receipt)
    }"#;

const COMPANIONS: &[Companion] = &[
    Companion {
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
                8 * 1024 * 1024, sqlite.clone(),
                &crucible_cas::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process"),
            )"#,
            "sqlite: Arc<ComponentSqliteSupervisor>",
            "_scratch: scratch, sqlite,",
            r#"pub(in crate::campaign_gc) fn supervision(&self) -> HostOperationSupervisor {
                self.sqlite.supervisor.clone()
            }"#,
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
    },
    Companion {
        path: "crates/crucible-daemon/src/campaign_gc/reachability/batched_tests.rs",
        required: &[PUBLISHED_REFUSAL],
        counts: &[("fn put_many_if_absent_with_boundary(", 1)],
    },
    Companion {
        path: "crates/crucible-daemon/src/campaign_gc/reachability/sorted_runs.rs",
        required: &[
            "if self.failed { return Err(terminal_failure()); }",
            "self.failed = result.is_err(); result",
            "if self.page.len() == PAGE { self.flush()?; }",
            "let node = writer.finish()?.ok_or(StoreError::Quota)?;",
            "run = self.merge(left, run)?; level += 1;",
            "self.operation.check()?; if level >= self.levels.len() { return Err(StoreError::Quota); }",
            "self.levels[..level].fill(None); self.levels[level] = Some(run); self.page.clear();",
            "let mut left_entry = left_cursor.next_entry()?; let mut right_entry = right_cursor.next_entry()?;",
            "while left_entry.is_some() || right_entry.is_some()",
            "let node = writer.finish()?.ok_or(StoreError::Quota)?; self.operation.check()?; Ok(RunRef { node, weight })",
            "self.flush()?; self.page = Vec::new();",
            "build_from_sorted_with_boundary(cursor, &account, &mut || { self.operation.check() })",
            "if root.entry_count() != run.node.count",
            "account.check().map_err(|error| mark_admission(&account, error))?; self.operation.check()?;",
            "if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64",
            "if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 { return Err(StoreError::Quota); } marks.root = root;",
        ],
        counts: &[("self.flush()?;", 2), ("marks.root = root;", 1)],
    },
    Companion {
        path: "crates/crucible-daemon/src/campaign_gc/reachability/sorted_runs/cursor.rs",
        required: &[
            r#"if self.failed { return Err(StoreError::Unsupported { capability: "failed-GC-run-cursor", }); }"#,
            "if result.is_err() { self.failed = true; }",
            "if self.remaining == 0 { reader.finish()?; }",
            "self.leaf = None;",
            "if self.observed != self.root.count || self.previous != Some(self.root.last)",
            "self.operation.check()?; self.complete = true; return Ok(None);",
            "self.backend.read_with_boundary(self.operation.original(), expected.id, None, &mut || self.operation.check(),)?",
            "source.read_all_with_boundary(self.operation.original(), format::MAX_PAGE_BYTES, &mut || self.operation.check(),)?",
            "match format::decode(expected.id, &bytes)?",
            "if node != expected { return Err(StoreError::Corrupt { id: expected.id }); }",
            "if node != expected || self.depth + 2 > self.pending.len()",
        ],
        counts: &[("self.complete = true;", 1)],
    },
];

#[cfg(test)]
mod tests {
    use super::super::pattern;
    use super::*;

    fn matches(source: &str, companions: &[String]) -> bool {
        let source = pattern(source);
        [CARRY_REFUSAL, COMPLETE_TAIL]
            .iter()
            .all(|body| source.contains(&pattern(body)))
            && [
                "fn failed_run_publication_retains_page_heads_and_original_mark_root(",
                "fn complete_run_tail_and_fallible_builder_tail_keep_initiating_cause(",
            ]
            .iter()
            .all(|name| source.match_indices(&pattern(name)).count() == 1)
            && companions.len() == COMPANIONS.len()
            && COMPANIONS.iter().zip(companions).all(|(binding, source)| {
                let source = pattern(source);
                binding
                    .required
                    .iter()
                    .all(|part| source.contains(&pattern(part)))
                    && binding
                        .counts
                        .iter()
                        .all(|(part, count)| source.match_indices(&pattern(part)).count() == *count)
            })
    }

    fn inputs() -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
        let root = super::super::super::super::super::workspace_root();
        let source = std::fs::read_to_string(
            root.join("crates/crucible-daemon/src/campaign_gc/reachability/sorted_runs/tests.rs"),
        )?;
        let companions = COMPANIONS
            .iter()
            .map(|binding| std::fs::read_to_string(root.join(binding.path)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((source, companions))
    }

    #[test]
    fn gc_sorted_runs_require_retained_heads_terminal_refusal_and_complete_tails()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source, companions) = inputs()?;
        assert!(matches(&source, &companions));
        let compact = pattern(&source);
        for (required_body, before, after) in [
            (
                CARRY_REFUSAL,
                "sorter.insert(page((4 * PAGE - 1) as u64)).unwrap_err()",
                "sorter.insert(page((4 * PAGE - 1) as u64)).unwrap()",
            ),
            (CARRY_REFUSAL, "before_carry + 3", "before_carry + 2"),
            (
                CARRY_REFUSAL,
                "error.original_failure()",
                "error.foreign_failure()",
            ),
            (
                CARRY_REFUSAL,
                "assert_eq!(marks.root, prior);",
                "removed_root_custody();",
            ),
            (
                CARRY_REFUSAL,
                "assert_eq!(sorter.page.len(), PAGE);",
                "removed_page_custody();",
            ),
            (
                CARRY_REFUSAL,
                "actual.map(|run| run.node) == expected.map(|run| run.node)",
                "true",
            ),
            (
                CARRY_REFUSAL,
                "assert_eq!(backend.publications.load(Ordering::Relaxed), before);",
                "removed_zero_effects();",
            ),
            (
                CARRY_REFUSAL,
                "operation.original().verify_live().unwrap();",
                "foreign.original().verify_live().unwrap();",
            ),
            (
                COMPLETE_TAIL,
                "assert!(!cursor.complete);",
                "removed_tail_acceptance();",
            ),
            (
                COMPLETE_TAIL,
                "assert!(cursor.next_entry().is_err());",
                "removed_sticky_tail();",
            ),
            (
                COMPLETE_TAIL,
                r#"let input = [ Ok(entry), Err(StoreError::Unsupported { capability: "authenticated-input-tail-failure", }), ];"#,
                "let input = [Ok(entry), Ok(entry)];",
            ),
            (
                COMPLETE_TAIL,
                "build_from_sorted_with_boundary(input, &account, &mut || operation.check(),)",
                "build_from_sorted_with_boundary(input, &account, &mut || foreign.check(),)",
            ),
        ] {
            let body = pattern(required_body);
            let before = pattern(before);
            assert!(compact.contains(&body), "missing required control body");
            assert!(
                body.contains(&before),
                "missing mutation preimage: {before}"
            );
            let changed_body = body.replacen(&before, &pattern(after), 1);
            let changed = compact.replacen(&body, &changed_body, 1);
            assert!(
                !matches(&changed, &companions),
                "removed current mark obligation: {before}"
            );
        }
        for addition in [
            "fn conceal() { retry(); }",
            "fn conceal() { retry!(); }",
            "fn conceal() { retry_failed_test(); }",
        ] {
            let code = super::super::super::super::scrub_comments_and_strings(&format!(
                "{source}\n{addition}"
            ));
            let code = super::super::mask(
                "crucible-daemon",
                "src/campaign_gc/reachability/sorted_runs/tests",
                &code,
            );
            assert!(
                super::super::super::super::flaky_escape_failures(
                    "unreviewed",
                    "unreviewed",
                    &code
                )
                .iter()
                .any(|finding| finding.contains("`retry`")),
                "unreviewed retry admitted: {addition}"
            );
        }
        Ok(())
    }

    #[test]
    fn gc_sorted_runs_require_one_original_fixture_clock_catalog_and_tail_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source, companions) = inputs()?;
        assert!(matches(&source, &companions));
        assert!(!matches(&source, &[]));
        for (index, binding) in COMPANIONS.iter().enumerate() {
            let compact = pattern(&companions[index]);
            for obligation in binding.required {
                let before = pattern(obligation);
                assert!(
                    compact.contains(&before),
                    "missing companion obligation: {} {before}",
                    binding.path
                );
                let mut changed = companions.clone();
                changed[index] = compact.replace(&before, "removed_original_obligation()");
                assert!(
                    !matches(&source, &changed),
                    "removed companion obligation admitted: {} {before}",
                    binding.path
                );
            }
            for (part, count) in binding.counts {
                let part = pattern(part);
                assert_eq!(compact.match_indices(&part).count(), *count);
                let mut changed = companions.clone();
                changed[index] = format!("{compact}{part}");
                assert!(
                    !matches(&source, &changed),
                    "additional original action admitted: {} {part}",
                    binding.path
                );
            }
        }
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
            ("sqlite.clone()", "foreign_sqlite.clone()"),
            (
                "_scratch: scratch, sqlite,",
                "_scratch: scratch, sqlite: foreign_sqlite,",
            ),
            (
                "self.sqlite.supervisor.clone()",
                "foreign.supervisor.clone()",
            ),
        ] {
            let before = pattern(before);
            let compact = pattern(&companions[0]);
            assert!(
                compact.contains(&before),
                "missing fixture preimage: {before}"
            );
            let mut changed = companions.clone();
            changed[0] = compact.replace(&before, &pattern(after));
            assert!(
                !matches(&source, &changed),
                "changed original fixture admitted: {before}"
            );
        }
        Ok(())
    }
}
