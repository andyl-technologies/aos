//! Binds the resource-free component launcher's cleanup delegation.
//!
//! The adapter exists only for tests or explicit test support. Its launch and
//! replay operations refuse production authority; empty component cleanup
//! supplies no native World, Service, Source or physical-return evidence.

use super::Contract;

const COMPONENT: &str = r###"#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PackagedProductionVmNodeLauncher;

#[cfg(any(test, feature = "test-support"))]
impl crucible_control_api::ProductionVmCleanupOwner for PackagedProductionVmNodeLauncher {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        // This component launcher owns no native World or Service return.
        Ok(None)
    }

    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ProductionVmNodeLauncher for PackagedProductionVmNodeLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _qemu_executable: &Path,
        _root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production replay authority",
        ))
    }

    fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        Ok(())
    }
}"###;

const DELEGATION: &str = r###"    fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmNodeLauncher::finish(self)
    }"###;

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/node_launcher",
    required: &[COMPONENT],
    expressions: &[(DELEGATION, 1)],
    companions: &[],
}];

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::mask_with_companions;

    fn has_retry(code: &str) -> bool {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    }

    fn source() -> Result<String, std::io::Error> {
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), "crucible-daemon")
            .join("src/vm_lifecycle/node_launcher.rs");
        Ok(crate::scrub_comments_and_strings(&std::fs::read_to_string(
            path,
        )?))
    }

    #[test]
    fn component_cleanup_classification_requires_the_exact_test_only_adapter()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let code = source()?;

        assert!(has_retry(&code));
        assert!(!has_retry(&mask_with_companions(contract, &code, &[])));
        let added = format!("{code}\nfn unrelated_retry() {{ retry(); }}");
        assert!(has_retry(&mask_with_companions(contract, &added, &[])));

        Ok(())
    }

    #[test]
    fn component_cleanup_classification_rejects_authority_or_delegation_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let code = source()?;
        let component = crate::scrub_comments_and_strings(COMPONENT);
        assert!(
            code.contains(&component),
            "missing actual component adapter"
        );

        for (before, after) in [
            (
                "#[cfg(any(test, feature =",
                "#[cfg(any(unreviewed, feature =",
            ),
            ("ProductionVmNodeLauncher::finish(self)", "Ok(())"),
            ("Ok(None)", "unreviewed_post_body()"),
            ("Err(loop_factory_error(", "Ok(unreviewed_native_launch("),
            (
                "fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {\n        Ok(())\n    }",
                "fn finish(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> { unreviewed_effect() }",
            ),
        ] {
            assert!(
                component.contains(before),
                "missing component owner: {before}"
            );
            let changed = code.replacen(&component, &component.replacen(before, after, 1), 1);
            assert_ne!(changed, code, "mutation did not alter the actual adapter");
            assert!(
                has_retry(&mask_with_companions(contract, &changed, &[])),
                "unreviewed component authority was accepted: {before}"
            );
        }

        Ok(())
    }
}
