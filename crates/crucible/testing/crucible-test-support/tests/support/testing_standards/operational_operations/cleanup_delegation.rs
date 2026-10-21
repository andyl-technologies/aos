//! Classifies effect-free cleanup signatures and one same-owner delegation.
//!
//! The exact declarations and tiny delegation methods grant no work. Runtime
//! cleanup calls, new attempts, waits and owning implementations stay outside
//! these contracts; the whole-source inventory and matcher remain unchanged.

use super::{Companion, Contract};

const OWNER_DECLARATION: &str = r#"pub trait ProductionVmCleanupOwner: Send {
    type Failure: std::error::Error + Send + 'static;
    type PostBody: Send + 'static;
    fn retry_cleanup(&mut self) -> Result<(), Self::Failure>;
    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure>;
}"#;

const HANDOFF_SIGNATURE: &str =
    "fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;";

pub(super) const CLEANUP_BOX_ALIASES: &str = r##"pub type ProductionVmCleanupReservationBox<Failure, PostBody, ReturnDestination> = Box<
    dyn ProductionVmCleanupReservation<
            Failure = Failure,
            PostBody = PostBody,
            ReturnDestination = ReturnDestination,
        >,
>;

/// Returns the original reservation when preparation cannot transfer its destination.
///
/// The refusal carries the same token and preserves its occupied cleanup cell.
pub type ProductionVmCleanupPrepareResult<Failure, PostBody, ReturnDestination> = Result<
    ReturnDestination,
    ProductionVmCleanupReservationBox<Failure, PostBody, ReturnDestination>,
>;

/// Names the existing boxed driver for one authenticated cleanup cell.
///
/// The same allocation remains responsible for its physical stage and history.
pub type ProductionVmCleanupHandoffBox<Failure, PostBody> =
    Box<dyn ProductionVmCleanupHandoff<Failure = Failure, PostBody = PostBody>>;

/// Preserves both original owners when a cleanup-cell transfer refuses.
///
/// Success carries the existing handoff token. Failure returns that same
/// reservation and containing body together, without allocating replacements.
pub type ProductionVmCleanupRetainResult<Failure, PostBody, ReturnDestination> = Result<
    ProductionVmCleanupHandoffBox<Failure, PostBody>,
    (
        ProductionVmCleanupReservationBox<Failure, PostBody, ReturnDestination>,
        Box<dyn ProductionVmCleanupOwner<Failure = Failure, PostBody = PostBody>>,
    ),
>;"##;

const CLEANUP_DECLARATIONS: &[(&str, usize)] = &[
    (CLEANUP_BOX_ALIASES, 1),
    (OWNER_DECLARATION, 1),
    ("type Failure: std::error::Error + Send + 'static;", 3),
    ("type PostBody: Send + 'static;", 3),
    ("type ReturnDestination: Send + 'static;", 1),
    (
        r#"pub trait ProductionVmCleanupHandoff: Send {
    type Failure: std::error::Error + Send + 'static;
    type PostBody: Send + 'static;
    fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;"#,
        1,
    ),
    (
        "fn stage(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;",
        1,
    ),
    ("fn first_failure(&self) -> Option<&Self::Failure>;", 1),
    ("fn retain_post_body(&mut self) -> bool;", 1),
    (
        "fn retained_post_body(&self) -> Option<&Self::PostBody>;",
        1,
    ),
    ("fn dispose(self: Box<Self>);", 1),
    (
        r#"fn into_post_body(
        self: Box<Self>,
    ) -> Result<Self::PostBody, ProductionVmCleanupHandoffBox<Self::Failure, Self::PostBody>>;"#,
        1,
    ),
    (
        r#"fn prepare_return(
        self: Box<Self>,
    ) -> ProductionVmCleanupPrepareResult<Self::Failure, Self::PostBody, Self::ReturnDestination>;"#,
        1,
    ),
    (
        "pub enum ProductionVmCleanupStage { BodyRetained, BodyDestroyed, Complete, }",
        1,
    ),
];

// This one shared method includes both body boundaries. A loop, another
// statement, foreign receiver or success fallback cannot preserve this match.
const SAME_OWNER_FORWARDER: &str = r#"fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
    ProductionVmNodeLauncher::finish(self)
}"#;

// This suffix keeps the scanned method name visible when an omission
// mutation removes its parameters. Each forwarding owner and its matching
// launcher finish now share the type; the census includes both signatures.
const FORWARDER_PARAMETERS: &str =
    "(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError>";
const OWNER_IMPLEMENTATION: &str = "impl crucible_control_api::ProductionVmCleanupOwner for";
const ONE_FORWARDER: &[(&str, usize)] = &[
    (OWNER_IMPLEMENTATION, 1),
    (FORWARDER_PARAMETERS, 2),
    (
        "type Failure = crate::ProductionVmConstructionCleanupError;",
        1,
    ),
    (
        "type PostBody = crate::ProductionVmConstructionPostBody;",
        1,
    ),
];
const FOUR_FORWARDERS: &[(&str, usize)] = &[
    (OWNER_IMPLEMENTATION, 4),
    (FORWARDER_PARAMETERS, 8),
    (
        "type Failure = crate::ProductionVmConstructionCleanupError;",
        4,
    ),
    (
        "type PostBody = crate::ProductionVmConstructionPostBody;",
        4,
    ),
];

const FORWARDING_COMPANIONS: &[Companion] = &[
    Companion {
        path: "crates/crucible/control/crucible-control-api/src/cleanup_owner.rs",
        required: CLEANUP_DECLARATIONS,
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle.rs",
        required: &[
            (
                r#"pub use crucible_control_api::{
    ProductionVmCleanupHandoff, ProductionVmCleanupOwner, ProductionVmCleanupReservation,
    ProductionVmCleanupStage,
};"#,
                1,
            ),
            (
                "fn finish(&mut self) -> Result<(), LifecycleApiError>; }",
                1,
            ),
        ],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/node_launcher.rs",
        required: &[
            (
                "pub trait ProductionVmNodeLauncher: ProductionVmCleanupOwner<Failure = crate::ProductionVmConstructionCleanupError, PostBody = crate::ProductionVmConstructionPostBody,> {",
                1,
            ),
            (
                "fn finish(&mut self) -> Result<(), ProductionVmConstructionCleanupError>; }",
                1,
            ),
        ],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/qemu_hot_fork_world_resource/node_target.rs",
        required: &[
            (
                "pub(crate) fn finish_member(&mut self) -> Result<(), QemuWorldMemberCleanupStatus>",
                1,
            ),
            ("state.guard.finish(", 0),
            (
                "state.released.insert(self.identity.clone()); self.retirement = WorldMemberRetirement::Returned; Ok(())",
                1,
            ),
            (
                "retire_unpublished_after_cleanup(registration.target, registration.resources)",
                2,
            ),
        ],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/qemu_hot_fork_reconciliation/linux.rs",
        required: &[
            ("target: QemuHotForkWorldNodeTarget<G>,", 2),
            ("pub(crate) fn into_world_node_adoption(", 1),
            (
                "slot: &mut Option<Self>, identity: ProductionVmNodeGeneration, completed: LinuxQemuHotForkWorldReconciliationSet<G>,",
                1,
            ),
            ("let Some(child) = slot.as_mut() else", 1),
            ("backend.target.identity() != &identity", 1),
            ("let process = match backend.installed_node.as_ref()", 1),
            ("let Some(mut child) = slot.take() else", 1),
            (
                "let lease = LinuxQemuHotForkWorldNodeLease { identity: identity.clone(), reconciliation: Some(child), completed, diagnostics_reported: false, live_diagnostics_enabled: diagnostics::live_diagnostics_enabled(), };",
                1,
            ),
        ],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/qemu_hot_fork_reconciliation/linux/reconciliation.rs",
        required: &[(
            "fn release_target(&mut self) -> Result<(), Self::Error> { self.run_directory = None; self.target.finish_member().map_err(Into::into) }",
            1,
        )],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/qemu_hot_fork_reconciliation/launch.rs",
        required: &[
            (
                "LinuxQemuHotForkReconciliationBackend::from_world_launch(",
                1,
            ),
            ("LinuxQemuHotForkReconciliationBackend<G>", 1),
        ],
    },
    Companion {
        path: "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
        required: &[
            (
                "pub(super) struct MissingStorage { pub(super) first: LifecycleApiError, pub(super) partial: Mutex<Partial>, pub(super) existing: Option<Box<ProductionVmConstructionCustody>>, }",
                1,
            ),
            (
                "first_guard: crate::QemuAttemptResourceGuardCleanupFailure,",
                1,
            ),
            (
                "second_guard: crate::QemuAttemptResourceGuardCleanupFailure,",
                1,
            ),
            (
                "(Err(first), Err(existing)) => Err(first.with_later_failure(existing)),",
                1,
            ),
            ("first.and(existing)", 0),
        ],
    },
];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-control-api",
        target: "src/cleanup_owner",
        required: CLEANUP_DECLARATIONS,
        expressions: &[(HANDOFF_SIGNATURE, 1)],
        identifiers: &[("retry_cleanup", 1)],
        companions: &[Companion {
            path: "crates/crucible/control/crucible-control-api/src/lib.rs",
            required: &[
                ("pub mod cleanup_owner;", 1),
                (
                    r#"pub use cleanup_owner::{
    ProductionVmCleanupHandoff, ProductionVmCleanupOwner, ProductionVmCleanupReservation,
    ProductionVmCleanupStage,
};"#,
                    1,
                ),
            ],
        }],
    },
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/helpers",
        required: ONE_FORWARDER,
        expressions: &[(SAME_OWNER_FORWARDER, 1)],
        identifiers: &[],
        companions: FORWARDING_COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/hot_fork/tests",
        required: ONE_FORWARDER,
        expressions: &[(SAME_OWNER_FORWARDER, 1)],
        identifiers: &[],
        companions: FORWARDING_COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/hot_fork/tests/retained_continuation",
        required: ONE_FORWARDER,
        expressions: &[(SAME_OWNER_FORWARDER, 1)],
        identifiers: &[],
        companions: FORWARDING_COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/runtime/tests",
        required: FOUR_FORWARDERS,
        expressions: &[(SAME_OWNER_FORWARDER, 4)],
        identifiers: &[],
        companions: FORWARDING_COMPANIONS,
    },
    Contract {
        package: "crucible-daemon",
        target: "src/vm_lifecycle/runtime/tests/held_stop",
        required: ONE_FORWARDER,
        expressions: &[(SAME_OWNER_FORWARDER, 1)],
        identifiers: &[],
        companions: FORWARDING_COMPANIONS,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_declarations_and_forwarders_reject_added_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                crate::workspace::package_path(&root.join("crates"), contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let code = crate::scrub_comments_and_strings(&source);
            let companions = super::super::read_companions(contract)?;
            let rejects = |candidate: &str| {
                let masked = super::super::mask_contract(contract, candidate, &companions);
                !crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty()
            };
            assert!(
                !rejects(&code),
                "reviewed declaration changed: {}",
                contract.target
            );

            if contract.package == "crucible-control-api" {
                for (declaration, effect) in [
                    (
                        HANDOFF_SIGNATURE,
                        "fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError> { unreviewed_effect(); }",
                    ),
                    (
                        "fn retry_cleanup(&mut self) -> Result<(), Self::Failure>;",
                        "fn retry_cleanup(&mut self) -> Result<(), Self::Failure> { unreviewed_effect(); }",
                    ),
                    (
                        "fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure>;",
                        "fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> { unreviewed_effect(); }",
                    ),
                    (
                        "fn retain_post_body(&mut self) -> bool;",
                        "fn retain_post_body(&mut self) -> bool { unreviewed_effect(); }",
                    ),
                ] {
                    let declaration = super::super::source_pattern(declaration);
                    let changed = super::super::replace_one_obligation(&code, &declaration, effect);
                    assert!(
                        rejects(&changed),
                        "default cleanup body was classified as a declaration"
                    );
                }
                for replacement in [
                    "",
                    "type Failure = crate::ProductionVmConstructionCleanupError;",
                ] {
                    let changed = code.replacen(
                        "type Failure: std::error::Error + Send + 'static;",
                        replacement,
                        1,
                    );
                    assert_ne!(changed, code);
                    assert!(
                        rejects(&changed),
                        "missing/default associated failure passed"
                    );
                }
                for declaration in [
                    "type PostBody: Send + 'static;",
                    "type ReturnDestination: Send + 'static;",
                ] {
                    let changed = code.replacen(declaration, "", 1);

                    assert_ne!(changed, code);
                    assert!(rejects(&changed), "missing return-custody type passed");
                }
                continue;
            }
            let changed = code.replacen(
                "type Failure = crate::ProductionVmConstructionCleanupError;",
                "type Failure = OtherFailure;",
                1,
            );
            assert_ne!(changed, code);
            assert!(rejects(&changed), "foreign forwarding failure type passed");
            let changed = code.replacen(
                "type PostBody = crate::ProductionVmConstructionPostBody;",
                "type PostBody = OtherPostBody;",
                1,
            );

            assert_ne!(changed, code);
            assert!(rejects(&changed), "foreign forwarding postbody type passed");
            for replacement in [
                "loop { ProductionVmNodeLauncher::finish(self) }",
                "{ unreviewed_effect(); ProductionVmNodeLauncher::finish(self) }",
                "ProductionVmNodeLauncher::finish(other)",
            ] {
                let changed = code.replace("ProductionVmNodeLauncher::finish(self)", replacement);
                assert_ne!(changed, code);
                assert!(
                    rejects(&changed),
                    "changed forwarding method passed: {}",
                    contract.target
                );
            }
            let method_pattern = super::super::source_pattern(SAME_OWNER_FORWARDER);
            let after_effect = format!(
                "{}; unreviewed_effect(); Ok(()) }}",
                SAME_OWNER_FORWARDER.trim_end_matches('}')
            );
            let changed =
                super::super::replace_one_obligation(&code, &method_pattern, &after_effect);
            assert!(
                rejects(&changed),
                "added post-delegation statement passed: {}",
                contract.target
            );
            let changed = code.replace(
                "ProductionVmNodeLauncher::finish(self)",
                "ProductionVmNodeLauncher::finish(self).map_err(|error| { unreviewed_effect(); error })",
            );
            assert_ne!(changed, code);
            assert!(
                rejects(&changed),
                "added error-path effect passed: {}",
                contract.target
            );
            let changed = code.replace(
                "ProductionVmNodeLauncher::finish(self)",
                "ProductionVmNodeLauncher::finish(self).map_err(|_error| crate::ProductionVmConstructionCleanupError::Pending)",
            );
            assert_ne!(changed, code);
            assert!(rejects(&changed), "typed cleanup leaf erasure passed");
        }
        Ok(())
    }

    #[test]
    fn cleanup_owner_forwarding_requires_the_actual_member_and_two_body_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[1];
        let root = crate::workspace_root();
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(
            crate::workspace::package_path(&root.join("crates"), contract.package)
                .join(format!("{}.rs", contract.target)),
        )?);
        let companions = super::super::read_companions(contract)?;
        let rejects = |evidence: &[String]| {
            let masked = super::super::mask_contract(contract, &code, evidence);
            !crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty()
        };
        assert!(!rejects(&companions));
        for (path, needle, replacement) in [
            (
                "node_target.rs",
                "pub(crate) fn finish_member",
                "pub(crate) fn missing_member",
            ),
            (
                "node_target.rs",
                "state.released.insert(self.identity.clone());",
                "state.guard.finish(); state.released.insert(self.identity.clone());",
            ),
            (
                "linux.rs",
                "target: QemuHotForkWorldNodeTarget<G>,",
                "target: G,",
            ),
            (
                "linux/reconciliation.rs",
                "self.target.finish_member()",
                "self.target.finish()",
            ),
            (
                "launch.rs",
                "LinuxQemuHotForkReconciliationBackend::from_world_launch(",
                "LinuxQemuHotForkReconciliationBackend::from_world_launch(LinuxQemuHotForkReconciliationBackend::from_world_launch(",
            ),
            (
                "custody.rs",
                "Err(first.with_later_failure(existing))",
                "first.and(Err(existing))",
            ),
        ] {
            let mut changed = companions.clone();
            let index = contract
                .companions
                .iter()
                .position(|binding| binding.path.ends_with(path))
                .unwrap();
            assert!(changed[index].contains(needle));
            changed[index] = changed[index].replacen(needle, replacement, 1);
            assert!(
                rejects(&changed),
                "lost actual cleanup ownership restriction: {path}: {needle}"
            );
        }
        Ok(())
    }
}
