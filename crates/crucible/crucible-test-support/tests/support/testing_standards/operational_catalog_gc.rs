//! Classifies one same-original Catalog restart and authenticated publication.
//!
//! The reviewed closure and its two calls are operational recovery observations.
//! Changed authority, missing assertions and additional attempts remain visible
//! to the existing flaky-test scanner.

use super::{Companion, Contract, mask_with_companions, pattern, read_companions};

// The interrupted owners close before reopen. A surviving corrupt Catalog must
// fail before exact-byte restoration; the next call must authenticate the root
// and retire both journals under the same original operation.
const RECOVERY: &str = r#"let mut retry = || {
            transfer_campaign_archive_durably_with_boundary(
                &mut CampaignArchiveTransferEndpoint::new(
                    self.source,
                    &mut source_journal,
                    "source",
                    true,
                ),
                &mut CampaignArchiveTransferEndpoint::new(
                    &restarted.repository,
                    &mut destination_journal,
                    "destination",
                    true,
                ),
                self.plan,
                "partial",
                None,
                self.durability,
                &mut || {
                    self.original
                        .wait_slice()
                        .expect("same original restart boundary");
                    Ok(())
                },
            )
        };
        if matches!(self.stage, PartialStage::SurvivingCatalog) {
            let failure =
                retry().expect_err("surviving Catalog is authenticated, never trusted by name");
            assert!(
                has_corruption(&failure, self.parent),
                "same Catalog corruption remains primary: {failure:?}"
            );
            assert!(!object_path(&destination_root, self.plan.ram_roots()[0]).exists());
            fs::write(&target_path, &saved_bytes).expect("restore exact original Catalog bytes");
        }
        let receipt =
            retry().expect("restart authenticates surviving or recopies collected Catalog");
        assert_eq!(receipt.operation(), self.operation);
        if self.stage.has_completed_root() {
            assert!(receipt.transfer().existing_objects > 0);
        }
        assert!(object_path(&destination_root, self.parent).exists());
        let destination_bytes =
            fs::read(object_path(&destination_root, self.parent)).expect("actual Catalog bytes");
        if target == self.parent {
            assert_eq!(destination_bytes.as_slice(), saved_bytes.as_slice());
        } else {
            let source_bytes = self
                .source
                .blob_backend()
                .read_with_boundary(self.source_original, self.parent, None, &mut || Ok(()))
                .expect("source Catalog")
                .read_all_with_boundary(self.source_original, 4 * 1024 * 1024, &mut || Ok(()))
                .expect("complete source Catalog");
            assert_eq!(destination_bytes.as_slice(), &*source_bytes);
        }
        assert_eq!(
            restarted
                .repository
                .inspect_campaign_archive_ref_with_boundary("partial", &mut || {
                    self.original
                        .wait_slice()
                        .expect("same original final authentication boundary");
                    Ok(())
                })
                .expect("complete authenticated archive after restart")
                .manifest_id(),
            self.plan.manifest_id()
        );
        assert!(
            !source_journal
                .contains(self.operation)
                .expect("source ownership retired")
        );
        assert!(
            !destination_journal
                .contains(self.operation)
                .expect("destination ownership retired")
        );"#;

const INITIAL_PROGRESS: &str = r#"assert!(observation.reached.load(Ordering::Acquire));
        if matches!(stage, PartialStage::CompletedRootSyncFailure) {
            assert!(!stopped);
            assert!(matches!(
                result,
                Err(CampaignArchiveTransferError::Journal(
                    CampaignTransferJournalError::Io { .. }
                ))
            ));
        } else {
            assert!(stopped, "exact transfer boundary reached: {result:?}");
            assert!(has_cancellation(
                &result.expect_err("no closure/durability receipt on cancellation")
            ));
        }
        observation.armed.store(false, Ordering::Release);
        assert_no_destination_refs(&destination);
        assert_journal(&source_journal, &plan, plan.ram_roots());
        let completed = if stage.has_completed_root() {
            plan.ram_roots()
        } else {
            &[]
        };
        let destination_generation = assert_journal(&destination_journal, &plan, completed);
        if stage.has_completed_root() {
            let direct_journal = DirectoryCampaignTransferJournal::open(
                temporary.path().join("direct-generation-comparison"),
            )
            .expect("direct comparison journal");
            direct_journal
                .begin(operation, TransferJournalRole::Destination, &plan)
                .expect("direct comparison record");
            let direct_generation = assert_journal(&direct_journal, &plan, &[]);
            assert_ne!(destination_generation, direct_generation);
        }"#;

const REOPENED_PROGRESS: &str = r#"assert_journal(&source_journal, self.plan, self.plan.ram_roots());
        let completed = if self.stage.has_completed_root() {
            self.plan.ram_roots()
        } else {
            &[]
        };
        assert_journal(&destination_journal, self.plan, completed);
        if matches!(self.stage, PartialStage::CompletedRootSyncFailure) {
            destination_journal
                .begin(self.operation, TransferJournalRole::Destination, self.plan)
                .expect("retry begin preserves visible completed progress");
            fail_next_directory_sync();
            assert!(matches!(
                destination_journal
                    .record_ram_closure_stored(self.operation, self.plan.ram_roots()[0]),
                Err(CampaignTransferJournalError::Io { .. })
            ));
            destination_journal
                .record_ram_closure_stored(self.operation, self.plan.ram_roots()[0])
                .expect("idempotent completed-root retry resyncs the record");
            assert_journal(&destination_journal, self.plan, self.plan.ram_roots());
        }"#;

const COMPLETED_ROOT_GC: &str = r#"let prepared = plan_single_host_campaign_gc_with_transfers(
                &restarted.repository,
                restarted.refs_admin.as_ref(),
                &mut ledger,
                None,
                &destination_journal,
                None,
                maintenance,
            )
            .expect("reopened completed RAM root is traversed after failed publication");
            for retained in [self.plan.ram_roots()[0], self.parent, self.page] {
                assert!(
                    prepared
                        .candidates()
                        .iter()
                        .all(|candidate| candidate.id() != retained),
                    "completed RAM descendant remains transitively retained"
                );
            }
            let (mut journal, _) = DirectoryCampaignGcJournal::create(
                self.temporary
                    .path()
                    .join("actual-complete-root-gc-journal"),
                &prepared,
                &operation,
            )
            .expect("durable actual GC plan");
            let report = apply_single_host_campaign_gc_with_transfers(
                &mut journal,
                &restarted.repository,
                restarted.refs_admin.as_ref(),
                &mut ledger,
                None,
                &destination_journal,
                None,
                maintenance,
            )
            .expect("apply preserves completed RAM closure after restart");
            assert_eq!(report.status(), crate::CampaignGcApplyStatus::Applied);
            assert!(object_path(&destination_root, self.parent).exists());
            assert!(object_path(&destination_root, self.page).exists());"#;

const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/campaign_transfer/tests/catalog_gc",
    required: &[
        RECOVERY,
        INITIAL_PROGRESS,
        REOPENED_PROGRESS,
        COMPLETED_ROOT_GC,
        r#"let saved_original = self.destination.original.clone();
            let _scope = saved_original.enter();"#,
        r#"let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(Duration::from_secs(300));
                    HOST_OPERATION_CLASS_COUNT],
            },
            Some(Duration::from_secs(300)),
        ).expect("existing finite operation ceiling");
        let original = supervisor.begin(HostOperationClass::Transfer)
            .expect("one original boundary");"#,
        r#"original.wait_slice().expect("same original transfer deadline");"#,
        r#"source_original: &source.original,
            original: &original,"#,
        r#"drop(source_journal_observer);
            drop(destination_journal_observer);"#,
        r#".finish();
            drop(root);
        }
        source_owner.assert_idle();
        destination_owner.assert_idle();"#,
        r#"drop(self.destination);
        drop(self.source_journal);
        drop(self.destination_journal);

        let restarted = self.destination_owner.reopen(&refs_root, &saved_original);
        let mut source_journal = DirectoryCampaignTransferJournal::open(self.source_journal_root)
            .expect("actual reopened source journal");
        let mut destination_journal =
            DirectoryCampaignTransferJournal::open(self.destination_journal_root)
                .expect("actual reopened destination journal");"#,
        "assert_no_destination_refs(&restarted);",
        r#"fn catalog_with_missing_child_is_collected_then_recopied_after_restart() {
            run_partial_transfer(PartialStage::MissingChild);
        }"#,
        r#"fn catalog_with_corrupt_child_is_collected_without_following_orphan_links() {
            run_partial_transfer(PartialStage::CorruptChild);
        }"#,
        r#"fn surviving_catalog_is_authenticated_before_restart_completion() {
            run_partial_transfer(PartialStage::SurvivingCatalog);
        }"#,
        r#"fn completed_ram_root_survives_failed_publication_restart_and_real_gc() {
            run_partial_transfer(PartialStage::CompletedRoot);
        }"#,
        r#"fn visible_completed_ram_progress_survives_directory_sync_failure_and_retry() {
            run_partial_transfer(PartialStage::CompletedRootSyncFailure);
        }"#,
    ],
    expressions: &[
        ("let mut retry = || {", 1),
        ("retry()", 2),
        (
            "fn visible_completed_ram_progress_survives_directory_sync_failure_and_retry()",
            1,
        ),
    ],
    companions: &[Companion {
        path: "crates/crucible/crucible-daemon/src/campaign_transfer/tests/catalog_gc/fixture.rs",
        required: &[
            "const DESCRIPTORS: u64 = 256;",
            "const METADATA_BYTES: u64 = 64 * 1024 * 1024;",
            r#"let resources = HostServiceAllocator::new(1, DESCRIPTORS, METADATA_BYTES)
                .expect("original finite namespace");"#,
            r#"pub(super) fn reopen(&self, refs_root: &Path, original: &DecodeBudget)
                -> RepositoryNamespace {
                self.open_with_original(refs_root, Some(original.clone()))
            }"#,
            r#"let original = saved.unwrap_or_else(|| {
                DecodeBudget::for_store(self.guard.clone())
                    .expect("same original namespace decoding")
            });"#,
            r#"CampaignRamAdmission::Available(original.clone())"#,
            r#"let available = self.guard.resources
                .reserve_resources(0, DESCRIPTORS, METADATA_BYTES - self.structural_bytes)
                .expect("all transient credits returned to the same original");
            drop(available);"#,
        ],
        counts: &[
            ("HostServiceAllocator::new(", 1),
            ("DecodeBudget::for_store(", 1),
        ],
    }],
};

// These counts bind the five single entry points and one initial interruption
// plus one restart closure. A copied helper or another call is not classified.
const CALL_COUNTS: &[(&str, usize)] = &[
    ("run_partial_transfer(", 6),
    (".finish();", 1),
    ("transfer_campaign_archive_durably_with_boundary(", 2),
    ("HostOperationSupervisor::new(", 1),
    ("OriginalNamespace::new(", 2),
    ("assert_journal(", 7),
    ("fail_next_directory_sync(", 2),
    (".record_ram_closure_stored(", 2),
    ("plan_single_host_campaign_gc_with_transfers(", 2),
    ("apply_single_host_campaign_gc_with_transfers(", 2),
    ("stage.has_completed_root()", 5),
    ("#[test]", 5),
];

pub(super) fn mask(package: &str, target: &str, code: &str) -> Option<String> {
    if package != CONTRACT.package || target != CONTRACT.target {
        return None;
    }
    let Ok(companions) = read_companions(&CONTRACT) else {
        return Some(code.to_owned());
    };
    Some(mask_recovery(code, &companions))
}

fn mask_recovery(code: &str, companions: &[String]) -> String {
    if CALL_COUNTS.iter().any(|(expression, count)| {
        super::super::expression_offsets(code, &pattern(expression)).len() != *count
    }) {
        return code.to_owned();
    }
    mask_with_companions(&CONTRACT, code, companions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(code: &str, companions: &[String]) -> bool {
        super::super::super::super::flaky_escape_failures(
            "unreviewed",
            "unreviewed",
            &mask_recovery(code, companions),
        )
        .iter()
        .any(|finding| finding.contains("`retry`"))
    }

    fn input() -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
        let root = super::super::super::super::workspace_root();
        let source = std::fs::read_to_string(
            root.join("crates/crucible/crucible-daemon")
                .join(format!("{}.rs", CONTRACT.target)),
        )?;
        let code = super::super::super::super::scrub_comments_and_strings(&source);
        Ok((code, read_companions(&CONTRACT)?))
    }

    #[test]
    fn catalog_restart_requires_exact_recovery_and_single_attempts()
    -> Result<(), Box<dyn std::error::Error>> {
        let (code, companions) = input()?;
        let compact = super::super::compact_code(&code);
        assert!(!rejected(&code, &companions));
        for (before, after) in [
            ("letmutretry=||{", "letmutretry=||{extra_attempt();"),
            ("retry().expect_err()", "retry!().expect_err()"),
            (
                "letreceipt=retry().expect();",
                "letreceipt=loop{retry().expect()};",
            ),
            (
                "letreceipt=retry().expect();",
                "letreceipt=repeat!{retry().expect()};",
            ),
            (
                "assert!(has_corruption(&failure,self.parent),);",
                "removed_assertion();",
            ),
            (
                "assert!(!object_path(&destination_root,self.plan.ram_roots()[0]).exists());",
                "removed_assertion();",
            ),
            (
                "fs::write(&target_path,&saved_bytes).expect();",
                "removed_restoration();",
            ),
            (
                "assert_eq!(receipt.operation(),self.operation);",
                "removed_assertion();",
            ),
            (
                "assert!(receipt.transfer().existing_objects>0);",
                "assert_eq!(receipt.transfer().existing_objects,0);",
            ),
            (
                "assert_journal(&source_journal,&plan,plan.ram_roots());",
                "assert_journal(&source_journal,&plan,&[]);",
            ),
            (
                "letcompleted=ifstage.has_completed_root(){plan.ram_roots()}else{&[]};",
                "letcompleted=&[];",
            ),
            (
                "assert_ne!(destination_generation,direct_generation);",
                "assert_eq!(destination_generation,direct_generation);",
            ),
            (
                "Err(CampaignArchiveTransferError::Journal(CampaignTransferJournalError::Io{..}))",
                "Err(CampaignArchiveTransferError::Repository(_))",
            ),
            (
                "destination_journal.begin(self.operation,TransferJournalRole::Destination,self.plan).expect();",
                "removed_retry_begin();",
            ),
            (
                "destination_journal.record_ram_closure_stored(self.operation,self.plan.ram_roots()[0]).expect();",
                "removed_idempotent_resync();",
            ),
            (
                "assert_journal(&destination_journal,self.plan,self.plan.ram_roots());",
                "assert_journal(&destination_journal,self.plan,&[]);",
            ),
            (
                "all(|candidate|candidate.id()!=retained)",
                "any(|candidate|candidate.id()==retained)",
            ),
            (
                "assert!(object_path(&destination_root,self.page).exists());",
                "removed_completed_descendant_assertion();",
            ),
            (
                "assert!(!source_journal.contains(self.operation).expect());",
                "removed_assertion();",
            ),
            (
                "assert!(!destination_journal.contains(self.operation).expect());",
                "removed_assertion();",
            ),
            (
                "self.destination_owner.reopen(&refs_root,&saved_original)",
                "self.destination_owner.open(&refs_root)",
            ),
            (
                "drop(self.destination);",
                "letretained_destination=self.destination;",
            ),
            (
                "drop(self.source_journal);drop(self.destination_journal);",
                "retain_old_journals(self.source_journal,self.destination_journal);",
            ),
            (
                "assert_no_destination_refs(&restarted);",
                "removed_reopened_ref_assertion();",
            ),
            (
                "self.original.wait_slice().expect();",
                "foreign_original.wait_slice().expect();",
            ),
            ("Duration::from_secs(300)", "Duration::from_secs(301)"),
            (
                "run_partial_transfer(PartialStage::MissingChild);",
                "loop{run_partial_transfer(PartialStage::MissingChild);}",
            ),
            (
                "run_partial_transfer(PartialStage::MissingChild);",
                "repeat!{run_partial_transfer(PartialStage::MissingChild);}",
            ),
        ] {
            assert!(
                compact.contains(before),
                "mutation preimage absent: {before}"
            );
            let changed = compact.replacen(before, after, 1);
            assert!(
                rejected(&changed, &companions),
                "changed recovery admitted: {before}"
            );
        }
        for addition in [
            "retry();",
            "retry!();",
            "retry_failed_test();",
            "run_partial_transfer(PartialStage::MissingChild);",
            ".finish();",
            "loop{retry();}",
            "repeat!{retry();}",
        ] {
            assert!(
                rejected(&format!("{code}\n{addition}"), &companions),
                "additional attempt admitted: {addition}"
            );
        }
        assert!(mask("foreign", CONTRACT.target, &code).is_none());
        assert!(mask(CONTRACT.package, "foreign", &code).is_none());
        Ok(())
    }

    #[test]
    fn catalog_restart_requires_original_fixture_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let (code, companions) = input()?;
        assert!(rejected(&code, &[]));
        for (before, after) in [
            (
                "const DESCRIPTORS: u64 = 256;",
                "const DESCRIPTORS: u64 = 257;",
            ),
            (
                "const METADATA_BYTES: u64 = 64 * 1024 * 1024;",
                "const METADATA_BYTES: u64 = 65 * 1024 * 1024;",
            ),
            ("Some(original.clone())", "None"),
            (
                "DecodeBudget::for_store(self.guard.clone())",
                "DecodeBudget::for_store(foreign_guard.clone())",
            ),
            (
                "CampaignRamAdmission::Available(original.clone())",
                "CampaignRamAdmission::Unavailable",
            ),
        ] {
            assert!(
                companions[0].contains(before),
                "fixture preimage absent: {before}"
            );
            let changed = vec![companions[0].replacen(before, after, 1)];
            assert!(
                rejected(&code, &changed),
                "foreign fixture admitted: {before}"
            );
        }
        Ok(())
    }
}
