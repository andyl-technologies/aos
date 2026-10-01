//! Closed exact control intent retained atomically with generation receipts.
//!
//! Request correlation is intentionally absent from this durable record. New
//! nonces and deadlines can recover a lost control reply, while a changed kind,
//! denial CAS or installation remains a different operation.
//!
//! ```json
//! {"installation":{"format_version":1},"operation":{"kind":"install","input":{}}}
//! ```
//!
//! The abbreviated example omits mandatory installation/publication fields.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::{
    control::StorageAuthorityPublication,
    lease::control::{IssuerInstallation, IssuerOperation},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedControl {
    pub(super) installation: IssuerInstallation,
    pub(super) operation: IssuerOperation,
}

impl RetainedControl {
    pub(super) fn new(
        installation: &IssuerInstallation,
        operation: IssuerOperation,
    ) -> Result<Self> {
        let retained = Self {
            installation: installation.clone(),
            operation,
        };
        retained.validate(installation)?;
        Ok(retained)
    }

    pub(super) fn validate(&self, expected: &IssuerInstallation) -> Result<()> {
        self.installation.validate()?;
        ensure!(
            &self.installation == expected,
            "retained control audience changed"
        );
        let publication = match &self.operation {
            IssuerOperation::Install(publication) | IssuerOperation::Publish(publication) => {
                publication
            }
            IssuerOperation::Deny(denial) => {
                denial.validate(
                    &expected.authority.guard_namespace_id,
                    &expected.executor_identity,
                )?;
                &denial.publication
            }
            IssuerOperation::Current | IssuerOperation::Issue { .. } => {
                anyhow::bail!("operation has no publication receipt")
            }
        };
        publication.validate(
            &expected.authority.guard_namespace_id,
            &expected.executor_identity,
        )?;
        ensure!(
            publication.authority == expected.authority,
            "retained control authority differs"
        );
        if matches!(self.operation, IssuerOperation::Install(_)) {
            ensure!(
                publication.generation == 1 && publication.admission.expected_generation == 0,
                "retained installation is not first publication"
            );
        }
        Ok(())
    }

    pub(super) fn publication(&self) -> Result<&StorageAuthorityPublication> {
        match &self.operation {
            IssuerOperation::Install(publication) | IssuerOperation::Publish(publication) => {
                Ok(publication)
            }
            IssuerOperation::Deny(denial) => Ok(&denial.publication),
            IssuerOperation::Current | IssuerOperation::Issue { .. } => {
                anyhow::bail!("operation has no publication receipt")
            }
        }
    }
}
