//! Classifies effect-free cleanup signatures and one same-owner delegation.
//!
//! The exact declarations and tiny delegation methods grant no work. Runtime
//! cleanup calls, new attempts, waits and owning implementations stay outside
//! these contracts; the whole-source inventory and matcher remain unchanged.

use super::{Companion, Contract};

const OWNER_DECLARATION: &str = r#"pub trait ProductionVmCleanupOwner: Send {
    type Failure: std::error::Error + Send + 'static;
    fn retry_cleanup(&mut self) -> Result<(), Self::Failure>;
}"#;

const HANDOFF_SIGNATURE: &str =
    "fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;";

const CLEANUP_DECLARATIONS: &[(&str, usize)] = &[
    (OWNER_DECLARATION, 1),
    ("type Failure: std::error::Error + Send + 'static;", 3),
    (
        r#"pub trait ProductionVmCleanupHandoff: Send {
    type Failure: std::error::Error + Send + 'static;
    fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;"#,
        1,
    ),
    (
        "fn stage(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;",
        1,
    ),
    ("fn first_failure(&self) -> Option<&Self::Failure>;", 1),
    (
        "fn take_first_failure(&mut self) -> Option<Self::Failure>;",
        1,
    ),
];

// This one shared method includes both body boundaries. A loop, another
// statement, foreign receiver or success fallback cannot preserve this match.
const SAME_OWNER_FORWARDER: &str = r#"fn retry_cleanup(&mut self) -> Result<(), crucible::SchedulerError> {
    ProductionVmNodeLauncher::finish(self).map_err(|error| {
        crucible::SchedulerError::BoundaryViolation {
            message: error.to_string(),
        }
    })
}"#;

// This suffix keeps the scanned method name visible when an omission
// mutation removes its parameters. The expression binds the entire method.
const FORWARDER_PARAMETERS: &str = "(&mut self) -> Result<(), crucible::SchedulerError>";
const OWNER_IMPLEMENTATION: &str = "impl crucible_api::ProductionVmCleanupOwner for";
const ONE_FORWARDER: &[(&str, usize)] = &[
    (OWNER_IMPLEMENTATION, 1),
    (FORWARDER_PARAMETERS, 1),
    ("type Failure = crucible::SchedulerError;", 1),
];
const FOUR_FORWARDERS: &[(&str, usize)] = &[
    (OWNER_IMPLEMENTATION, 4),
    (FORWARDER_PARAMETERS, 4),
    ("type Failure = crucible::SchedulerError;", 4),
];

const FORWARDING_COMPANIONS: &[Companion] = &[
    Companion {
        path: "crates/crucible-api/src/cleanup_owner.rs",
        required: CLEANUP_DECLARATIONS,
    },
    Companion {
        path: "crates/crucible-daemon/src/vm_lifecycle.rs",
        required: &[
            (
                "pub trait ProductionVmNodeLauncher: ProductionVmCleanupOwner<Failure = crucible::SchedulerError> {",
                1,
            ),
            (
                r#"pub use crucible_api::{
    ProductionVmCleanupHandoff, ProductionVmCleanupOwner, ProductionVmCleanupReservation,
    ProductionVmCleanupStage,
};"#,
                1,
            ),
            (
                "fn finish(&mut self) -> Result<(), LifecycleApiError>; }",
                2,
            ),
        ],
    },
];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-api",
        target: "src/cleanup_owner",
        required: &[
            ("pub trait ProductionVmCleanupOwner: Send {", 1),
            ("type Failure: std::error::Error + Send + 'static;", 3),
            ("(&mut self) -> Result<(), Self::Failure>;", 1),
            ("pub trait ProductionVmCleanupHandoff: Send {", 1),
            (
                "(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;",
                2,
            ),
            ("fn first_failure(&self) -> Option<&Self::Failure>;", 1),
            (
                "fn take_first_failure(&mut self) -> Option<Self::Failure>;",
                1,
            ),
            (
                "pub enum ProductionVmCleanupStage { BodyRetained, BodyDestroyed, Complete, }",
                1,
            ),
        ],
        expressions: &[(HANDOFF_SIGNATURE, 1)],
        identifiers: &[("retry_cleanup", 1)],
        companions: &[Companion {
            path: "crates/crucible-api/src/lib.rs",
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
                root.join("crates")
                    .join(contract.package)
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

            if contract.package == "crucible-api" {
                for (declaration, effect) in [
                    (
                        HANDOFF_SIGNATURE,
                        "fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError> { unreviewed_effect(); }",
                    ),
                    (
                        "fn retry_cleanup(&mut self) -> Result<(), Self::Failure>;",
                        "fn retry_cleanup(&mut self) -> Result<(), Self::Failure> { unreviewed_effect(); }",
                    ),
                ] {
                    let declaration = super::super::source_pattern(declaration);
                    let changed = super::super::replace_one_obligation(&code, &declaration, effect);
                    assert!(
                        rejects(&changed),
                        "default cleanup body was classified as a declaration"
                    );
                }
                for replacement in ["", "type Failure = crucible::SchedulerError;"] {
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
                continue;
            }
            let changed = code.replacen(
                "type Failure = crucible::SchedulerError;",
                "type Failure = OtherFailure;",
                1,
            );
            assert_ne!(changed, code);
            assert!(rejects(&changed), "foreign forwarding failure type passed");
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
                "message: error.to_string(),",
                "message: { unreviewed_effect(); error.to_string() },",
            );
            assert_ne!(changed, code);
            assert!(
                rejects(&changed),
                "added error-path effect passed: {}",
                contract.target
            );
        }
        Ok(())
    }
}
