//! Classifies one same-original Catalog restart and authenticated publication.
//!
//! The reviewed closure and its two calls are operational recovery observations.
//! Changed authority, missing assertions and additional attempts remain visible
//! to the existing flaky-test scanner.

use super::{Companion, Contract, mask_with_companions, pattern, read_companions};

// The interrupted owners close before reopen. A surviving corrupt Catalog must
// fail before exact-byte restoration; the next call must authenticate the root
// and retire both journals under the same original operation.
const RECOVERY: &str = r#"drop(self.destination);
        drop(self.source_journal);
        drop(self.destination_journal);

        let restarted = self.destination_owner.reopen(&refs_root, &saved_original);
        let mut source_journal = DirectoryCampaignTransferJournal::open(self.source_journal_root)
            .expect("actual reopened source journal");
        let mut destination_journal =
            DirectoryCampaignTransferJournal::open(self.destination_journal_root)
                .expect("actual reopened destination journal");
        assert_direct_journal(&source_journal, self.plan);
        assert_direct_journal(&destination_journal, self.plan);
        assert_no_destination_refs(&restarted);
        let mut retry = || {
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

const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/campaign_transfer/tests/catalog_gc",
    required: &[
        RECOVERY,
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
        r#"assert!(has_cancellation(
            &result.expect_err("no closure/durability receipt on cancellation")
        ));
        observation.armed.store(false, Ordering::Release);
        assert_no_destination_refs(&destination);
        assert_direct_journal(&source_journal, &plan);
        assert_direct_journal(&destination_journal, &plan);"#,
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
        r#"fn catalog_with_missing_child_is_collected_then_recopied_after_restart() {
            run_partial_transfer(PartialStage::MissingChild);
        }"#,
        r#"fn catalog_with_corrupt_child_is_collected_without_following_orphan_links() {
            run_partial_transfer(PartialStage::CorruptChild);
        }"#,
        r#"fn surviving_catalog_is_authenticated_before_restart_completion() {
            run_partial_transfer(PartialStage::SurvivingCatalog);
        }"#,
    ],
    expressions: &[("let mut retry = || {", 1), ("retry()", 2)],
    companions: &[Companion {
        path: "crates/crucible-daemon/src/campaign_transfer/tests/catalog_gc/fixture.rs",
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

// These counts bind the three single entry points and one initial interruption
// plus one restart closure. A copied helper or another call is not classified.
const CALL_COUNTS: &[(&str, usize)] = &[
    ("run_partial_transfer(", 4),
    (".finish();", 1),
    ("transfer_campaign_archive_durably_with_boundary(", 2),
    ("HostOperationSupervisor::new(", 1),
    ("OriginalNamespace::new(", 2),
    ("#[test]", 3),
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
            root.join("crates/crucible-daemon")
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
