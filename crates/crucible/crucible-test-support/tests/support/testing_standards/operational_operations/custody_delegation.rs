//! Classifies the effect-free construction-custody cleanup delegation.
//!
//! The complete same-owner method and its concrete body/handback companions
//! remain bound together. These source checks grant no Native operation or
//! physical-return qualification and never classify another caller's retries.

use super::{Companion, Contract};

const FORWARDER: &str = r#"fn retry_cleanup(&mut self) -> Result<(), crate::ProductionVmConstructionCleanupError> {
        ProductionVmConstructionCustody::retry_cleanup(self)
    }"#;

const COMPANIONS: &[Companion] = &[
    Companion {
        path: "crates/crucible/crucible-daemon/src/vm_lifecycle/construction/custody.rs",
        required: &[(
            r#"pub fn retry_cleanup(&self) -> Result<(), ProductionVmConstructionCleanupError> {
        let mut phase = self.phase.try_lock().map_err(phase_lock_error)?;
        if self.physically_closed.load(Ordering::Acquire) {
            return Ok(());
        }
        match &mut *phase {
            Phase::Partial(partial) => retire_partial(partial)?,
            Phase::Complete(lifecycle) => retire_complete(lifecycle)?,
            #[cfg(target_os = "linux")]
            Phase::Source(source) => source.retry_source_retirement_body()?,
            #[cfg(target_os = "linux")]
            Phase::SharedSource(source) => source.retry_body()?,
            #[cfg(target_os = "linux")]
            Phase::SourceRearmFailure(source) => source.retry_body()?,
            #[cfg(target_os = "linux")]
            Phase::SourcePreparation(preparation) => preparation.retry_body()?,
            Phase::Empty => return Ok(()),
        }
        // Keep the actual phase in this carrier. The canonical queue destroys
        // it outside the cell mutex, then returns the containing-body lease.
        // A later factual retry observes closure without repeating effects.
        self.physically_closed.store(true, Ordering::Release);
        Ok(())
    }"#,
            1,
        )],
    },
    Companion {
        path: "crates/crucible/crucible-daemon/src/vm_lifecycle/construction/custody/post_body.rs",
        required: &[(
            r#"fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        if !self.physically_closed.load(Ordering::Acquire) {
            return Err(Self::Failure::Retained(
                "construction body cleanup is not complete",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            if self.post_body.is_none() {
                let phase = self.phase.get_mut().map_err(|_| Self::Failure::Poisoned)?;
                let body = match phase {
                    Phase::Partial(partial) => match partial.node_launcher.as_mut() {
                        Some(launcher) => launcher.take_post_body()?,
                        None => None,
                    },
                    Phase::Complete(lifecycle) => {
                        let body = lifecycle.node_launcher.take_post_body()?;
                        body
                    }
                    #[cfg(target_os = "linux")]
                    Phase::Source(source) => source.take_source_retirement_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SharedSource(source) => source.take_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SourceRearmFailure(source) => source.take_post_body()?,
                    #[cfg(target_os = "linux")]
                    Phase::SourcePreparation(preparation) => preparation.take_post_body()?,
                    Phase::Empty => None,
                };
                self.post_body = body;
            }
            let phase = self.phase.get_mut().map_err(|_| Self::Failure::Poisoned)?;
            if let Phase::Complete(lifecycle) = phase {
                lifecycle.transfer_retained_debug_construction(&mut self.post_body)?;
            }
            if self.first.is_some() && self.post_body.is_none() {
                self.post_body = Some(crate::ProductionVmConstructionPostBody::history_only());
            }
            if let Some(first) = self.first.take() {
                if let Some(body) = self.post_body.as_mut() {
                    if let Err(first) = body.retain_constructor_first(first) {
                        self.first = Some(first);
                        return Err(Self::Failure::Retained(
                            "construction first still occupies its original body",
                        ));
                    }
                } else {
                    self.first = Some(first);
                    return Err(Self::Failure::Retained(
                        "construction history destination is absent",
                    ));
                }
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(destination) = self.return_destination.take() {
            destination.cancel_for_owned_body();
        }
        Ok(self.post_body.take())
    }"#,
            1,
        )],
    },
];

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/construction/custody/post_body",
    required: &[
        (
            "impl crucible_control_api::ProductionVmCleanupOwner for ProductionVmConstructionCustody",
            1,
        ),
        (
            "type Failure = crate::ProductionVmConstructionCleanupError;",
            1,
        ),
        (
            "type PostBody = crate::ProductionVmConstructionPostBody;",
            1,
        ),
    ],
    expressions: &[(FORWARDER, 1)],
    identifiers: &[],
    companions: COMPANIONS,
}];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_forwarder_rejects_foreign_owners_added_effects_and_erased_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[0];
        let path = crate::workspace::package_path(
            &crate::workspace_root().join("crates"),
            contract.package,
        )
        .join(format!("{}.rs", contract.target));
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
        let companions = super::super::read_companions(contract)?;
        let callee = "ProductionVmConstructionCustody::retry_cleanup(self)";

        for replacement in [
            "ProductionVmConstructionCustody::retry_cleanup(foreign)",
            "loop { ProductionVmConstructionCustody::retry_cleanup(self) }",
            "{ unreviewed_effect(); ProductionVmConstructionCustody::retry_cleanup(self) }",
            "ProductionVmConstructionCustody::retry_cleanup(self).or(Ok(()))",
            "ProductionVmConstructionCustody::retry_cleanup(self).map_err(|_| erased_failure())",
        ] {
            let changed = code.replace(callee, replacement);
            assert_ne!(changed, code);
            let masked = super::super::mask_contract(contract, &changed, &companions);
            assert_eq!(masked, changed);
            assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
        }
        Ok(())
    }
}
