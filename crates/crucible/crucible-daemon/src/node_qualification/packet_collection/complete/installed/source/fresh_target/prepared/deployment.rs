//! Joins actual prepared Source rows to one retained deployment reservation.
//!
//! The selected path creates only isolated templates and declarations. The
//! original reservation funds the shared operational process domain; it does
//! not supply Initial, Recipe, a worker result, native startup or readiness.

use super::*;
use crate::node_control::deployment::InstalledDeployment;
use crucible_engine::node_contract::RuntimeError;
use crucible_host_resources::DeploymentResourceReadContext;

impl PreparedCompleteRestoration {
    /// Constructs funded isolated templates under an actual original deployment.
    ///
    /// The original was installed before actors, then moved to this actor. This
    /// private route accepts installation/8 or closed configuration/1. A recipe
    /// creates one local Host/coordinator before deriving any initial or launch
    /// reference and retains that exact Host. The route never invokes the old
    /// selected-forbidden bank/BirthWorker stages or creates lifecycle success.
    pub(crate) fn prepare_with_deployment_into(
        manifest: InstalledCompleteSceneManifest,
        directory: PathBuf,
        limits: NativeArchiveLimits,
        deployment: Rc<InstalledDeployment>,
        output: &mut Option<Self>,
    ) -> Result<(), QualificationError> {
        if output.is_some() {
            return Err(refused());
        }
        deployment.authenticate().map_err(|_| refused())?;
        use super::super::super::super::manifest::{FundedSelection, load_funded};
        deployment.note_operation_stage("loading funded configuration");
        match load_funded(&manifest)? {
            FundedSelection::Installation(selected, selection) => Self::prepare_selected_into(
                selected,
                Some(selection),
                Some(deployment),
                directory,
                limits,
                output,
            ),
            FundedSelection::Configuration(configuration) => {
                deployment.note_operation_stage("materializing funded configuration");
                let (selected, host, selection) = configuration.materialize()?;
                Self::prepare_with_code_host_into(
                    selected,
                    Some(selection),
                    Some(deployment),
                    Some((host, manifest)),
                    directory,
                    limits,
                    output,
                )
            }
        }
    }

    /// Bounds whole-file code fetches by the actual funded scene and parent.
    ///
    /// Cold archive decoder limits apply to later archive records. This code
    /// graph instead authenticates complete executable files, under the pinned
    /// operator content policy and the original whole-parent reservation.
    ///
    /// # Errors
    /// Refuses a revoked reservation, unavailable original policy, zero budget
    /// or a ceiling that cannot be represented on this host.
    pub(super) fn funded_code_content_limits_data(
        &self,
    ) -> Result<Option<(usize, usize)>, QualificationError> {
        let Some(deployment) = &self.import18_templates.deployment else {
            return Ok(None);
        };
        deployment.authenticate().map_err(|_| refused())?;
        let context = deployment.context().map_err(|_| refused())?;
        let parent = context.reserved_policy_data().map_err(|_| refused())?;
        let maximum = self
            .selected
            .resources
            .content_bytes
            .get()
            .min(self.selected.resources.memory_bytes.get())
            .min(parent.address_space_bytes);
        let maximum = usize::try_from(maximum).map_err(|_| refused())?;
        if maximum == 0 {
            return Err(refused());
        }
        // Both per-object and cumulative fetches remain within this ceiling.
        // The actual reader charges every fetch, including repeated bodies.
        Ok(Some((maximum, maximum)))
    }

    pub(super) fn note_funded_operation_stage(&self, stage: &'static str) {
        if let Some(deployment) = &self.import18_templates.deployment {
            deployment.note_operation_stage(stage);
        }
    }

    pub(crate) fn authenticate_funded_templates_data(&self) -> Result<(), QualificationError> {
        self.note_funded_operation_stage("authenticating funded templates");
        if !self.import18_templates.funded_complete
            || self.import18_templates.complete
            || self.import18_templates.failed
        {
            return Err(refused());
        }
        self.observe_funded_templates_data([0; 3])
            .map_err(|_| refused())
    }

    /// Computes the known peak using this holder's original component observers.
    pub(super) fn observe_funded_templates_data(
        &self,
        demand: [usize; 3],
    ) -> Result<(), RuntimeError> {
        self.authenticate_import18_template_scope_data()?;
        let deployment = self
            .import18_templates
            .deployment
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let context = deployment.context()?;
        let parent = usize::try_from(
            context
                .reserved_policy_data()
                .map_err(|_| RuntimeError::ForeignAuthority)?
                .address_space_bytes,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let source = usize::try_from(self.selected.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let maximum = source.min(parent);
        let scratch = Self::import18_template_counter_scratch_data()?
            .checked_add(
                PacketCompleteSemanticSource::isolated_template_deployment_counter_scratch_data(),
            )
            .and_then(|n| n.checked_add(std::mem::size_of::<DeploymentResourceReadContext<'_>>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut counter =
            crate::node_qualification::packet_collection::complete::retained::Counter::new(
                maximum
                    .checked_sub(scratch)
                    .ok_or(RuntimeError::ResourceLimit)?,
            );
        // This is the actual Prepared observer, including real Source-produced
        // external reads. A caller cannot substitute a numeric D or verdict.
        HostSource17SetupBorrow::prepared_data(self).charge_data(&mut counter, None)?;
        for bytes in demand {
            counter
                .add(bytes)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        deployment.authenticate()?;
        self.authenticate_import18_template_scope_data()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "deployment/tests.rs"]
pub(super) mod tests;
