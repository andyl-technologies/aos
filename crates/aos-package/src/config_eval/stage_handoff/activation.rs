//! Closed operation dispatch for the initrd-to-host stage handoff.
//!
//! This module owns the typed activation, completion, and continuation wire
//! formats. The initrd dispatcher accepts only its two boot-substrate
//! operations, and the host dispatcher derives fresh evidence from its own
//! authenticated image and static contract:
//!
//! ```text
//! activation -> initrd completion -> host continuation evidence
//! ```

use anyhow::{Result, ensure};
use aos_ability_model::{ExecutionStage, LocalKey};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::ImageIdentity;

pub(super) const ACTIVATION_SCHEMA: &str = "aos.ability.initrd-activation/v1";
const COMPLETION_SCHEMA: &str = "aos.ability.initrd-activation-completion/v1";
const CONTINUATION_SCHEMA: &str = "aos.ability.host-stage-continuation/v1";

/// Defines a checked sequence of operations for the initrd boot-substrate manager.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitrdActivation {
    pub(super) schema: String,
    pub(super) manager: InitrdManagerIdentity,
    pub(super) operations: Vec<InitrdOperation>,
}

impl InitrdActivation {
    pub(super) fn check(&self) -> Result<()> {
        ensure!(
            self.schema == ACTIVATION_SCHEMA,
            "unsupported typed initrd activation schema"
        );
        ensure!(
            self.manager
                == InitrdManagerIdentity {
                    stage: ExecutionStage::Initrd,
                    kind: InitrdManagerKind::BootSubstrate,
                },
            "typed initrd activation names another manager scope"
        );
        ensure!(
            !self.operations.is_empty() && self.operations.len() <= 16,
            "typed initrd activation must contain between one and sixteen operations"
        );

        validate_ordered_ids(
            &self.operations,
            InitrdOperation::id,
            "typed initrd activation operation identifiers are not unique canonical order",
        )
    }
}

/// Identifies the one manager permitted to execute typed initrd operations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitrdManagerIdentity {
    pub(super) stage: ExecutionStage,
    pub(super) kind: InitrdManagerKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum InitrdManagerKind {
    BootSubstrate,
}

/// Enumerates all operations permitted during initrd activation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum InitrdOperation {
    AuthenticateTargetImage { id: LocalKey },
    VerifyStaticAbilityContract { id: LocalKey },
}

impl InitrdOperation {
    const fn id(&self) -> &LocalKey {
        match self {
            Self::AuthenticateTargetImage { id } | Self::VerifyStaticAbilityContract { id } => id,
        }
    }
}

/// Records the initrd manager's checked result for every selected operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitrdActivationCompletion {
    schema: String,
    manager: InitrdManagerIdentity,
    pub(super) operations: Vec<InitrdOperationCompletion>,
}

impl InitrdActivationCompletion {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == COMPLETION_SCHEMA,
            "unsupported initrd activation completion schema"
        );
        ensure!(
            self.manager.stage == ExecutionStage::Initrd
                && self.manager.kind == InitrdManagerKind::BootSubstrate,
            "initrd activation completion names another manager scope"
        );
        ensure!(
            !self.operations.is_empty() && self.operations.len() <= 16,
            "initrd activation completion has an invalid operation count"
        );

        validate_ordered_ids(
            &self.operations,
            InitrdOperationCompletion::id,
            "initrd activation completion identifiers are not unique canonical order",
        )
    }
}

/// Carries operation-specific facts established by the initrd manager.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum InitrdOperationCompletion {
    TargetImageAuthenticated { id: LocalKey, image: ImageIdentity },
    StaticAbilityContractVerified { id: LocalKey, sha256: Sha256Digest },
}

impl InitrdOperationCompletion {
    const fn id(&self) -> &LocalKey {
        match self {
            Self::TargetImageAuthenticated { id, .. }
            | Self::StaticAbilityContractVerified { id, .. } => id,
        }
    }
}

/// Records resources that the host independently reacquired and authorized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostContinuationEvidence {
    schema: String,
    manager_stage: ExecutionStage,
    pub(super) resources: Vec<HostResourceEvidence>,
}

impl HostContinuationEvidence {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == CONTINUATION_SCHEMA,
            "unsupported host continuation schema"
        );
        ensure!(
            self.manager_stage == ExecutionStage::Host,
            "continuation evidence names another receiving manager"
        );
        ensure!(
            !self.resources.is_empty() && self.resources.len() <= 16,
            "host continuation evidence has an invalid resource count"
        );

        validate_ordered_ids(
            &self.resources,
            HostResourceEvidence::id,
            "host continuation evidence identifiers are not unique canonical order",
        )
    }
}

/// Carries the host manager's independently established replacement facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum HostResourceEvidence {
    TargetImageReauthenticated { id: LocalKey, image: ImageIdentity },
    StaticAbilityContractReacquired { id: LocalKey, sha256: Sha256Digest },
}

impl HostResourceEvidence {
    const fn id(&self) -> &LocalKey {
        match self {
            Self::TargetImageReauthenticated { id, .. }
            | Self::StaticAbilityContractReacquired { id, .. } => id,
        }
    }
}

/// Dispatches only operations in the closed initrd boot-substrate vocabulary.
pub(super) struct InitrdStageManager<'a> {
    image: &'a ImageIdentity,
    contract_digest: Sha256Digest,
}

impl<'a> InitrdStageManager<'a> {
    pub(super) fn new(image: &'a ImageIdentity, contract_digest: Sha256Digest) -> Self {
        Self {
            image,
            contract_digest,
        }
    }

    pub(super) fn execute(
        &self,
        activation: &InitrdActivation,
    ) -> Result<InitrdActivationCompletion> {
        activation.check()?;
        let operations = activation
            .operations
            .iter()
            .map(|operation| match operation {
                InitrdOperation::AuthenticateTargetImage { id } => {
                    InitrdOperationCompletion::TargetImageAuthenticated {
                        id: id.clone(),
                        image: self.image.clone(),
                    }
                }
                InitrdOperation::VerifyStaticAbilityContract { id } => {
                    InitrdOperationCompletion::StaticAbilityContractVerified {
                        id: id.clone(),
                        sha256: self.contract_digest,
                    }
                }
            })
            .collect();
        let completion = InitrdActivationCompletion {
            schema: COMPLETION_SCHEMA.to_string(),
            manager: activation.manager,
            operations,
        };
        completion.validate()?;
        Ok(completion)
    }
}

/// Reauthorizes completion facts against the host's current trusted inputs.
pub(super) struct HostStageManager<'a> {
    image: &'a ImageIdentity,
    contract_digest: Sha256Digest,
}

impl<'a> HostStageManager<'a> {
    pub(super) fn new(image: &'a ImageIdentity, contract_digest: Sha256Digest) -> Self {
        Self {
            image,
            contract_digest,
        }
    }

    pub(super) fn continue_from(
        &self,
        completion: &InitrdActivationCompletion,
    ) -> Result<HostContinuationEvidence> {
        completion.validate()?;
        let resources = completion
            .operations
            .iter()
            .map(|operation| match operation {
                InitrdOperationCompletion::TargetImageAuthenticated { id, image } => {
                    ensure!(
                        image == self.image,
                        "host manager cannot reauthorize another target image"
                    );
                    Ok(HostResourceEvidence::TargetImageReauthenticated {
                        id: id.clone(),
                        image: self.image.clone(),
                    })
                }
                InitrdOperationCompletion::StaticAbilityContractVerified { id, sha256 } => {
                    ensure!(
                        *sha256 == self.contract_digest,
                        "host manager cannot reauthorize another static ability contract"
                    );
                    Ok(HostResourceEvidence::StaticAbilityContractReacquired {
                        id: id.clone(),
                        sha256: self.contract_digest,
                    })
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let evidence = HostContinuationEvidence {
            schema: CONTINUATION_SCHEMA.to_string(),
            manager_stage: ExecutionStage::Host,
            resources,
        };
        evidence.validate()?;
        Ok(evidence)
    }
}

fn validate_ordered_ids<T>(
    values: &[T],
    id: impl Fn(&T) -> &LocalKey,
    message: &'static str,
) -> Result<()> {
    let mut prior = None;
    for value in values {
        let current = id(value);
        ensure!(
            prior.as_ref().is_none_or(|prior_id| *prior_id < current),
            message
        );
        prior = Some(current);
    }
    Ok(())
}
