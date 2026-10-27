//! Constructs real fresh Source templates before archive tickets or native birth.
//!
//! Every step releases all Source loans before the complete Prepared census.
//! Private rows remain in their actual member; neither saved axes nor successful
//! template construction issue an archive, native model or startup permission.

use super::*;
use crate::node_control::deployment::InstalledDeployment;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_adapters::cnp::OriginalNativeSourceTemplate18MechanismQuote;
use crucible_engine::node_adapters::cnp::source_birth_derivation::job::SourceBirthDerivationJob;
use crucible_engine::node_adapters::cnp::{
    NativeImport18BirthConstructionQuote, OriginalImport18CaptureBankConstructionData,
    OriginalNativeSourceTemplate18Attempt, OriginalNativeSourceTemplate18ConstructionData,
};
use crucible_engine::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18InitialConstructionData, PacketNativeImport18LaunchIdentityData,
    PacketNativeImport18Selection,
};
use std::mem::{size_of, size_of_val};

#[path = "import18_templates/registration_plan.rs"]
mod registration_plan;

#[path = "import18_templates/mapping_custody.rs"]
mod mapping_custody;

#[path = "import18_derivation.rs"]
mod derivation;

pub(super) type Import18Selection = PacketNativeImport18Selection;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Unused,
    RegistrationPlan,
    Template,
    Declaration,
    Policy,
    Banks,
    BirthWorker,
    Complete,
    FundedTemplate,
    DerivationExporting,
    DerivationRunning,
    DerivedBanks,
    InitialBanks,
    PrivateSeed,
    PrivateBirth,
    MappingLease,
    DerivationFailed,
}

struct Member {
    stage: Stage,
    registration_row: Option<registration_plan::Quote>,
    registration: registration_plan::Attempt,
    template_row: Option<OriginalNativeSourceTemplate18ConstructionData>,
    mechanism_row: Option<OriginalNativeSourceTemplate18MechanismQuote>,
    declaration_row: Option<(usize, usize)>,
    bank_row: Option<OriginalImport18CaptureBankConstructionData>,
    birth_row: Option<NativeImport18BirthConstructionQuote>,
    output: OriginalNativeSourceTemplate18Attempt,
    job: Option<SourceBirthDerivationJob>,
    declaration_encoding_row: Option<[usize; 3]>,
    declaration_encoding: Option<Vec<u8>>,
    initial_projection: Option<PacketNativeImport18InitialConstructionData>,
    launch_identity: Option<PacketNativeImport18LaunchIdentityData>,
    mapping_nonce: Option<[u8; 32]>,
    mapping_lease_data: Option<([u8; 32], crucible_node_format::U64, [u8; 32])>,
}

impl Member {
    fn empty() -> Self {
        Self {
            stage: Stage::Unused,
            registration_row: None,
            registration: registration_plan::Attempt::empty(),
            template_row: None,
            mechanism_row: None,
            declaration_row: None,
            bank_row: None,
            birth_row: None,
            output: OriginalNativeSourceTemplate18Attempt::default(),
            job: None,
            declaration_encoding_row: None,
            declaration_encoding: None,
            initial_projection: None,
            launch_identity: None,
            mapping_nonce: None,
            mapping_lease_data: None,
        }
    }
}

pub(super) struct Templates {
    pub(super) deployment: Option<Rc<InstalledDeployment>>,
    pub(super) funded_complete: bool,
    started: bool,
    pub(super) complete: bool,
    pub(super) failed: bool,
    derivation_failure: Option<RuntimeError>,
    members: [Member; 3],
}

/// Stores references to each real member field, with no whole-Member reference.
struct MemberObservation<'a> {
    stage: &'a Stage,
    registration_row: &'a Option<registration_plan::Quote>,
    registration: &'a registration_plan::Attempt,
    template_row: &'a Option<OriginalNativeSourceTemplate18ConstructionData>,
    mechanism_row: &'a Option<OriginalNativeSourceTemplate18MechanismQuote>,
    declaration_row: &'a Option<(usize, usize)>,
    bank_row: &'a Option<OriginalImport18CaptureBankConstructionData>,
    birth_row: &'a Option<NativeImport18BirthConstructionQuote>,
    output: &'a OriginalNativeSourceTemplate18Attempt,
    job: &'a Option<SourceBirthDerivationJob>,
    declaration_encoding_row: &'a Option<[usize; 3]>,
    declaration_encoding: &'a Option<Vec<u8>>,
    initial_projection: &'a Option<PacketNativeImport18InitialConstructionData>,
    launch_identity: &'a Option<PacketNativeImport18LaunchIdentityData>,
    mapping_nonce: &'a Option<[u8; 32]>,
    mapping_lease_data: &'a Option<([u8; 32], crucible_node_format::U64, [u8; 32])>,
}

impl<'a> MemberObservation<'a> {
    fn from_member_data(member: &'a Member) -> Self {
        let Member {
            stage,
            registration_row,
            registration,
            template_row,
            mechanism_row,
            declaration_row,
            bank_row,
            birth_row,
            output,
            job,
            declaration_encoding_row,
            declaration_encoding,
            initial_projection,
            launch_identity,
            mapping_nonce,
            mapping_lease_data,
        } = member;
        Self {
            stage,
            registration_row,
            registration,
            template_row,
            mechanism_row,
            declaration_row,
            bank_row,
            birth_row,
            output,
            job,
            declaration_encoding_row,
            declaration_encoding,
            initial_projection,
            launch_identity,
            mapping_nonce,
            mapping_lease_data,
        }
    }
}

/// Observes all three actual members and keeps every inline flag explicit.
///
/// This ordinary shared view is not a selected mutable-state split API.
pub(super) struct TemplatesObservation<'a> {
    deployment: &'a Option<Rc<InstalledDeployment>>,
    funded_complete: &'a bool,
    started: &'a bool,
    complete: &'a bool,
    failed: &'a bool,
    derivation_failure: &'a Option<RuntimeError>,
    members: [MemberObservation<'a>; 3],
}

impl MemberObservation<'_> {
    fn charge_retained_data(
        &self,
        counter: &mut Counter,
        deployment: Option<&InstalledDeployment>,
    ) -> Result<(), RuntimeError> {
        let Self {
            stage,
            registration_row: _,
            registration,
            template_row: _,
            mechanism_row: _,
            declaration_row: _,
            bank_row: _,
            birth_row: _,
            output,
            job,
            declaration_encoding_row: _,
            declaration_encoding,
            initial_projection: _,
            launch_identity: _,
            mapping_nonce: _,
            mapping_lease_data: _,
        } = *self;
        if let Some(bank) = declaration_encoding {
            counter
                .add(bank.capacity())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        registration.charge_retained_data(counter)?;
        if let Some(job) = job {
            let context = deployment
                .ok_or(RuntimeError::ForeignAuthority)?
                .context()?;
            let read = job.deployment_storage_read(&context, counter.remaining())?;
            read.authenticate_original(&context)?;
            counter
                .add(read.known_requested_bytes_data())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        if let (Some(deployment), Some(source)) = (deployment, output.partial_data()) {
            let context = deployment.context()?;
            // Once this member retains its private Birth, count the complete
            // initial-lifecycle owners, including later Bootstrap journals.
            // The stage selects a data visitor; original Source/deployment
            // custody and unresolved native-read obligations remain mandatory.
            let read = if matches!(stage, Stage::PrivateBirth | Stage::MappingLease) {
                source.original_initial_lifecycle_deployment_storage_data(
                    &context,
                    counter.remaining(),
                )
            } else {
                source.original_isolated_template_deployment_storage_data(
                    &context,
                    counter.remaining(),
                )
            }?;
            read.authenticate_original(&context)?;
            counter
                .add(read.known_requested_bytes_data())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        } else {
            counter
                .add(output.retained_requested_storage_data(counter.remaining())?)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        Ok(())
    }
}

impl TemplatesObservation<'_> {
    pub(super) fn charge_retained_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        let Self {
            deployment,
            funded_complete: _,
            started: _,
            complete: _,
            failed: _,
            derivation_failure,
            members,
        } = self;
        // The owner is exactly this fixed three-slot array, not a policy limit.
        let [first, second, third] = members;
        let deployment = deployment.as_deref();
        if let Some(owner) = deployment {
            owner.authenticate()?;
            if counter
                .rc(self
                    .deployment
                    .as_ref()
                    .ok_or(RuntimeError::ForeignAuthority)?)
                .map_err(|_| RuntimeError::ResourceLimit)?
            {
                counter
                    .add(owner.known_direct_backing_data()?)
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
        }
        if let Some(RuntimeError::SchedulerRefused(message)) = derivation_failure {
            counter
                .add(message.capacity())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        first.charge_retained_data(counter, deployment)?;
        second.charge_retained_data(counter, deployment)?;
        third.charge_retained_data(counter, deployment)
    }
}

// New literal/helper windows only. Child observers keep their defining rows;
// no actual Source, registration backing or future mutable attempt is invented.
const fn member_field_references_data() -> usize {
    size_of::<&Stage>()
        + size_of::<&Option<registration_plan::Quote>>()
        + size_of::<&registration_plan::Attempt>()
        + size_of::<&Option<OriginalNativeSourceTemplate18ConstructionData>>()
        + size_of::<&Option<OriginalNativeSourceTemplate18MechanismQuote>>()
        + size_of::<&Option<(usize, usize)>>()
        + size_of::<&Option<OriginalImport18CaptureBankConstructionData>>()
        + size_of::<&Option<NativeImport18BirthConstructionQuote>>()
        + size_of::<&OriginalNativeSourceTemplate18Attempt>()
        + size_of::<&Option<SourceBirthDerivationJob>>()
        + size_of::<&Option<[usize; 3]>>()
        + size_of::<&Option<Vec<u8>>>()
        + size_of::<&Option<PacketNativeImport18InitialConstructionData>>()
        + size_of::<&Option<PacketNativeImport18LaunchIdentityData>>()
        + size_of::<&Option<[u8; 32]>>()
        + size_of::<&Option<([u8; 32], crucible_node_format::U64, [u8; 32])>>()
}

const MEMBER_PROJECTION_CONTROLS: usize = size_of::<&Member>() // from_member_data input
    + member_field_references_data() // exhaustive reference bindings
    + member_field_references_data() // actual field operands
    + size_of::<MemberObservation<'static>>() // literal initializer
    + size_of::<MemberObservation<'static>>(); // helper return

const TEMPLATE_PROJECTION_CONTROLS: usize = size_of::<&Option<RuntimeError>>() * 3
    + size_of::<&Option<Rc<InstalledDeployment>>>() * 2
    + size_of::<&bool>() * 2 // funded-complete reference binding and field operand
    + size_of::<Rc<InstalledDeployment>>() * 2 // selected wrapper and local holder
    + size_of::<&Templates>() // observation_data receiver
    + size_of::<&bool>() * 3 // actual flag bindings
    + size_of::<&[Member; 3]>() // members field binding
    + size_of::<&Member>() * 3 // fixed-three destructure bindings
    + MEMBER_PROJECTION_CONTROLS * 3 // three actual member constructions
    + size_of::<MemberObservation<'static>>() * 3 // array owned element inputs
    + size_of::<[MemberObservation<'static>; 3]>() // array initializer
    + size_of::<[MemberObservation<'static>; 3]>() // struct owned field operand
    + size_of::<&bool>() * 3 // flag field operands
    + size_of::<TemplatesObservation<'static>>() // literal initializer
    + size_of::<TemplatesObservation<'static>>() // observation_data return
    + size_of::<TemplatesObservation<'static>>() // ordinary wrapper temporary
    + size_of::<&TemplatesObservation<'static>>() // new charge receiver
    + size_of::<&mut Counter>() // new charge helper input
    + size_of::<&[MemberObservation<'static>; 3]>() // members view binding
    + size_of::<&MemberObservation<'static>>() * 3 // fixed-three shared bindings
    + MEMBER_CHARGE_CONTROLS * 3 // actual first/second/third method entries
    + super::host_setup17::runtime_try_controls_data::<(), ()>() * 2 // first/second ?
    + size_of::<Result<(), RuntimeError>>() // view forwarding return
    + size_of::<Result<(), RuntimeError>>(); // ordinary wrapper forwarding return

const MEMBER_CHARGE_CONTROLS: usize = size_of::<&MemberObservation<'static>>() // actual helper receiver
    + size_of::<&mut Counter>() // actual helper counter argument
    + size_of::<&Stage>() // copied stage view selects the actual component visitor
    + size_of::<bool>() // visitor selection comparison
    + size_of::<&registration_plan::Attempt>() // copied actual registration reference
    + size_of::<&OriginalNativeSourceTemplate18Attempt>() // copied actual output reference
    + size_of::<&Option<SourceBirthDerivationJob>>() // copied actual external job slot
    + size_of::<&Option<Vec<u8>>>()
    + size_of::<Option<&Vec<u8>>>()
    + size_of::<&Vec<u8>>()
    + size_of::<usize>()
    + size_of::<Result<(), QualificationError>>()
    + size_of::<Result<(), RuntimeError>>()
    + size_of::<()>() // member Ok constructor owned unit operand
    + size_of::<Result<(), RuntimeError>>() // member Ok initializer
    + size_of::<Result<(), RuntimeError>>(); // extra member-helper return

impl Templates {
    pub(super) fn empty() -> Self {
        Self::with_deployment(None)
    }

    pub(super) fn with_deployment(deployment: Option<Rc<InstalledDeployment>>) -> Self {
        Self {
            deployment,
            funded_complete: false,
            started: false,
            complete: false,
            failed: false,
            derivation_failure: None,
            members: std::array::from_fn(|_| Member::empty()),
        }
    }

    /// Projects every actual flag/member for the ordinary shared census.
    pub(super) fn observation_data(&self) -> TemplatesObservation<'_> {
        let Self {
            deployment,
            funded_complete,
            started,
            complete,
            failed,
            derivation_failure,
            members,
        } = self;
        let [first, second, third] = members;
        TemplatesObservation {
            deployment,
            funded_complete,
            started,
            complete,
            failed,
            derivation_failure,
            members: [
                MemberObservation::from_member_data(first),
                MemberObservation::from_member_data(second),
                MemberObservation::from_member_data(third),
            ],
        }
    }

    /// Counts every partial actual output, including failed declaration/banks.
    pub(super) fn charge_retained_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        self.observation_data().charge_retained_data(counter)
    }

    #[cfg(test)]
    /// Counts every partial actual output, including failed declaration/banks.
    pub(super) fn charge_unprojected_retained_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        // The enclosing Option<Prepared> already prices all inline rows/flags.
        if let Some(RuntimeError::SchedulerRefused(message)) = &self.derivation_failure {
            counter
                .add(message.capacity())
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        for member in &self.members {
            if let Some(bank) = &member.declaration_encoding {
                counter
                    .add(bank.capacity())
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            member.registration.charge_retained_data(counter)?;
            if let Some(job) = &member.job {
                let context = self
                    .deployment
                    .as_ref()
                    .ok_or(RuntimeError::ForeignAuthority)?
                    .context()?;
                let read = job.deployment_storage_read(&context, counter.remaining())?;
                read.authenticate_original(&context)?;
                counter
                    .add(read.known_requested_bytes_data())
                    .map_err(|_| RuntimeError::ResourceLimit)?;
            }
            counter
                .add(
                    member
                        .output
                        .retained_requested_storage_data(counter.remaining())?,
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        Ok(())
    }

    pub(super) fn retained_counter_scratch_data() -> usize {
        TEMPLATE_PROJECTION_CONTROLS
            + PreparedLaunches::counter_scratch_data()
            + OriginalNativeSourceTemplate18Attempt::retained_counter_scratch_data()
            + registration_plan::Attempt::counter_scratch_data()
            + SourceBirthDerivationJob::deployment_storage_counter_scratch_data()
            + PreparedCompleteRestoration::funded_initial_banks_counter_scratch_data()
            + PacketCompleteSemanticSource::initial_lifecycle_deployment_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Counter>()
            + size_of::<usize>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), QualificationError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl PreparedCompleteRestoration {
    /// Checks only genuine installed code custody before each fresh operation.
    pub(super) fn authenticate_import18_template_scope_data(
        &self,
    ) -> Result<Import18Selection, RuntimeError> {
        let selection = self
            .import18_selection
            .ok_or(RuntimeError::UnsupportedFacet)?;
        if self.selected.schema != "crucible.complete-scene.installation/7"
            || self.prebirth_attempted
            || self.prebirth.is_some()
            || self.restored_prebirth_attempt.is_some()
            || self.restored_prebirth_source.is_some()
            || self.installation_attempted
            || self.code_owners.is_none()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        self.code_factory
            .authenticate_prebirth_template18_custody_data(
                &self.code_authority,
                &self.code_plan,
                self.code_graph
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )?;
        Ok(selection)
    }

    /// Observes all actual old and new owners before the next stage effects.
    pub(super) fn observe_import18_templates_data(
        &self,
        demand: [usize; 3],
    ) -> Result<(), RuntimeError> {
        if self.import18_templates.deployment.is_some() {
            return self.observe_funded_templates_data(demand);
        }
        self.authenticate_import18_template_scope_data()?;
        let maximum = usize::try_from(self.selected.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let scratch = Self::import18_template_counter_scratch_data()?;
        let mut counter = Counter::new(
            maximum
                .checked_sub(scratch)
                .ok_or(RuntimeError::ResourceLimit)?,
        );
        HostSource17SetupBorrow::prepared_data(self).charge_data(&mut counter, None)?;
        for bytes in demand {
            counter
                .add(bytes)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        self.authenticate_import18_template_scope_data()?;
        Ok(())
    }

    pub(super) fn prepare_import18_templates_data(&mut self) -> Result<(), RuntimeError> {
        if self.import18_templates.started {
            return Err(RuntimeError::DuplicateOperation);
        }
        // Spend the real setup before the first quote, including unwind.
        self.note_funded_operation_stage("authenticating original template scope");
        self.import18_templates.started = true;
        self.import18_templates.failed = true;
        self.authenticate_import18_template_scope_data()?;
        let maximum = usize::try_from(self.selected.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;

        if self.import18_templates.deployment.is_some() {
            self.note_funded_operation_stage("retaining fresh original launches");
            self.retain_fresh_original_launches_data()?;
        }
        for selected in 0..3 {
            self.prepare_import18_member_data(selected, maximum)?;
        }
        self.observe_import18_templates_data([0; 3])?;
        if self.import18_templates.deployment.is_some() {
            self.import18_templates.funded_complete = true;
        } else {
            self.import18_templates.complete = true;
        }
        self.import18_templates.failed = false;
        Ok(())
    }

    fn prepare_import18_member_data(
        &mut self,
        selected: usize,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        let selection = self.authenticate_import18_template_scope_data()?;
        let coordinator_maximum = self
            .selected
            .maximum_coordinator_records
            .ok_or(RuntimeError::OwnerUnavailable)?;
        // Build the actual planned inputs before a fresh Source exists. This
        // is DATA only; the strict later import18 prebirth refusal stays closed.
        self.note_funded_operation_stage("constructing fresh registration plan");
        self.import18_templates.members[selected].stage = Stage::RegistrationPlan;
        self.import18_templates.members[selected]
            .registration
            .begin_data()?;
        self.observe_import18_templates_data([0; 3])?;
        let row =
            registration_plan::Quote::for_launch_data(self.launches.get(selected)?, selected)?;
        self.import18_templates.members[selected].registration_row = Some(row);
        self.observe_import18_templates_data(row.requested_storage_data())?;
        let result = self.import18_templates.members[selected]
            .registration
            .retain_into_data(
                self.launches.get(selected)?,
                selected,
                &row,
                row.requested_storage_data(),
            );
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;

        // No clone or Rc follows an arbitrary source argument. The input comes
        // directly from this same admitted code authority's fixed roster slot.
        self.observe_import18_templates_data([0; 3])?;
        // Prepared retains its original code_authority Rc throughout this
        // private synchronous quote/constructor interval and later censuses.
        // The raw code address inside ConstructionData is never an epoch.
        self.note_funded_operation_stage("quoting and constructing isolated Source template");
        if let Some(deployment) = self.import18_templates.deployment.clone() {
            let row = self
                .code_authority
                .roster()
                .sources
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?
                .native_source_template18_with_derivation_construction_data(
                    deployment.mechanism()?,
                    maximum,
                )?;
            let (retained, transient, scratch) = row.requested_storage_data();
            self.import18_templates.members[selected].mechanism_row = Some(row);
            self.import18_templates.members[selected].stage = Stage::Template;
            self.observe_import18_templates_data([retained, transient, scratch])?;
            let member = &mut self.import18_templates.members[selected];
            let result = self.code_authority.roster().sources[selected]
                .native_source_template18_with_derivation_into(
                    member
                        .mechanism_row
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    &mut member.output,
                );
            let observed = self.observe_import18_templates_data([0; 3]);
            result.and(observed)?;
        } else {
            let row = self
                .code_authority
                .roster()
                .sources
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?
                .native_source_template18_construction_data(maximum)?;
            self.import18_templates.members[selected].template_row = Some(row);
            self.import18_templates.members[selected].stage = Stage::Template;
            let (retained, transient, scratch) = row.requested_storage_data();
            self.observe_import18_templates_data([retained, transient, scratch])?;
            let result = self.code_authority.roster().sources[selected]
                .native_source_template18_into(
                    &row,
                    &mut self.import18_templates.members[selected].output,
                );
            let observed = self.observe_import18_templates_data([0; 3]);
            result.and(observed)?;
        }

        self.observe_import18_templates_data([0; 3])?;
        self.note_funded_operation_stage("binding isolated Source declaration");
        let declaration =
            PacketCompleteSemanticSource::native_import18_declaration_construction_storage_data(
                maximum,
            )?;
        self.import18_templates.members[selected].declaration_row = Some(declaration);
        self.import18_templates.members[selected].stage = Stage::Declaration;
        self.observe_import18_templates_data([0, declaration.0, declaration.1])?;
        let result = self.import18_templates.members[selected]
            .output
            .completed_unique_data()?
            .bind_native_import18_declaration_data(selection, self.launches.get(selected)?);
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;

        if self.import18_templates.deployment.is_some() {
            // Pure selected templates have no old native policy/bank/worker
            // capability. Their later isolated job is a separate actual owner.
            self.import18_templates.members[selected].stage = Stage::FundedTemplate;
            return Ok(());
        }

        self.import18_templates.members[selected].stage = Stage::Policy;
        self.observe_import18_templates_data([0, 0,
            PacketCompleteSemanticSource::original_restored_settled_coordinator_policy18_counter_scratch_data()])?;
        let result = self.import18_templates.members[selected]
            .output
            .completed_unique_data()?
            .bind_original_restored_settled_coordinator_policy18(coordinator_maximum);
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;

        self.observe_import18_templates_data([0; 3])?;
        let row = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .original_import18_capture_bank_construction_data(
                self.selected.maximum_native_rows,
                maximum,
            )?;
        self.import18_templates.members[selected].bank_row = Some(row);
        self.import18_templates.members[selected].stage = Stage::Banks;
        let (retained, transient, scratch) = row.requested_storage_data();
        self.observe_import18_templates_data([retained, transient, scratch])?;
        let result = self.import18_templates.members[selected]
            .output
            .completed_unique_data()?
            .reserve_original_import18_capture_banks_data(&row);
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;
        // The same immutable plan/Id change custody, not allocation history.
        // This creates only the failed-first Source input worker, never Birth.
        self.import18_templates.members[selected].stage = Stage::BirthWorker;
        self.observe_import18_templates_data([0; 3])?;
        let row = self.import18_templates.members[selected]
            .output
            .completed_data()?
            .native_import18_birth_initialize_quote_data(self.launches.get(selected)?, maximum)?;
        let demand = row.requested_storage_data();
        self.import18_templates.members[selected].birth_row = Some(row);
        self.observe_import18_templates_data(demand)?;
        let result = self.initialize_import18_member_birth_data(selected);
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;
        self.import18_templates.members[selected].stage = Stage::Complete;
        Ok(())
    }

    /// Releases every Source loan before the caller observes success or refusal.
    fn initialize_import18_member_birth_data(
        &mut self,
        selected: usize,
    ) -> Result<(), RuntimeError> {
        let member = &mut self.import18_templates.members[selected];
        let row = member
            .birth_row
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let source = member.output.completed_unique_data()?;
        member.registration.retain_source_initialize_into_data(
            source,
            self.launches.get(selected)?,
            row,
        )
    }

    fn import18_birth_handoff_counter_scratch_data() -> usize {
        size_of::<&mut Self>()
            + size_of::<usize>()
            + size_of::<&mut Member>()
            + size_of::<&mut PacketCompleteSemanticSource>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&NativeImport18BirthConstructionQuote>()
            + size_of::<Option<&NativeImport18BirthConstructionQuote>>()
            + size_of::<Result<&NativeImport18BirthConstructionQuote, RuntimeError>>()
            + size_of::<Result<&mut PacketCompleteSemanticSource, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
    }

    pub(super) fn import18_template_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms = [
            HostSource17SetupBorrow::counter_scratch_data()?,
            Self::import18_birth_handoff_counter_scratch_data(),
            registration_plan::Attempt::counter_scratch_data(),
            PacketCompleteSemanticSource::native_import18_birth_construction_counter_scratch_data(),
            PacketCompleteArchiveCodeFactory::prebirth_template18_custody_counter_scratch_data(),
            PacketCompleteSemanticSource::native_source_template18_counter_scratch_data(),
            PacketCompleteSemanticSource::native_import18_declaration_counter_scratch_data(),
            PacketCompleteSemanticSource::original_restored_settled_coordinator_policy18_counter_scratch_data(),
            PacketCompleteSemanticSource::original_import18_capture_bank_counter_scratch_data(),
            size_of::<Counter>(),
            size_of::<&Self>(),
            size_of::<&mut Self>(),
            size_of::<Templates>(),
            size_of::<Member>(),
            size_of::<NativeImport18BirthConstructionQuote>(),
            size_of::<Option<NativeImport18BirthConstructionQuote>>(),
            size_of::<Result<NativeImport18BirthConstructionQuote, RuntimeError>>(),
            size_of::<&NativeImport18BirthConstructionQuote>(),
            size_of::<Option<&NativeImport18BirthConstructionQuote>>(),
            size_of::<Result<&NativeImport18BirthConstructionQuote, RuntimeError>>(),
            size_of::<Stage>(),
            size_of::<OriginalNativeSourceTemplate18ConstructionData>(),
            size_of::<Option<OriginalNativeSourceTemplate18ConstructionData>>(),
            size_of::<OriginalImport18CaptureBankConstructionData>(),
            size_of::<Option<OriginalImport18CaptureBankConstructionData>>(),
            size_of::<Result<OriginalNativeSourceTemplate18ConstructionData, RuntimeError>>(),
            size_of::<Result<OriginalImport18CaptureBankConstructionData, RuntimeError>>(),
            size_of::<Import18Selection>(),
            size_of::<Result<Import18Selection, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<usize, std::num::TryFromIntError>>(),
            size_of::<Result<&mut PacketCompleteSemanticSource, RuntimeError>>(),
            size_of::<Result<&Rc<PacketCompleteSemanticSource>, RuntimeError>>(),
            size_of::<Option<&Rc<PacketCompleteSemanticSource>>>(),
            size_of::<Result<(usize, usize), RuntimeError>>(),
            size_of::<(usize, usize)>(),
            size_of::<(usize, usize, usize)>(),
            size_of::<[usize; 3]>(),
            size_of::<std::array::IntoIter<usize, 3>>(),
            size_of::<std::ops::Range<usize>>(),
            size_of::<[usize; 6]>(),
            size_of::<std::slice::Iter<'static, usize>>(),
            // The declaration retains its own fold total and borrowed term.
            size_of::<usize>(),
            size_of::<&usize>(),
            size_of::<Option<usize>>(),
            size_of::<Result<usize, RuntimeError>>(),
            // The mapping challenge remains Copy DATA beside the real Birth.
            size_of::<[u8; 32]>(),
            size_of::<Result<[u8; 32], RuntimeError>>() * 2,
            size_of::<&Member>(),
            size_of::<std::slice::Iter<'static, Member>>(),
            mapping_custody::counter_scratch_data(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

/// Uses the actual admitted fixture, never a fabricated graph/plan/native owner.
#[cfg(test)]
pub(super) fn assert_actual_code_custody_data(owner: &PreparedCompleteRestoration) {
    registration_plan::assert_actual_launch_data(&owner.launches.originals().unwrap()[0]);
    let graph = owner.code_graph.as_ref().unwrap();
    owner
        .code_factory
        .authenticate_prebirth_template18_custody_data(
            &owner.code_authority,
            &owner.code_plan,
            graph,
        )
        .unwrap();

    // A separately issued genuine plan with the same authority/evidence is not
    // the actual retained plan occurrence used by this code factory.
    let another = Rc::new(owner.code_authority.collection_plan().unwrap());
    assert!(!Rc::ptr_eq(&another, &owner.code_plan));
    assert!(
        owner
            .code_factory
            .authenticate_prebirth_template18_custody_data(&owner.code_authority, &another, graph,)
            .is_err()
    );
    // The ordinary constructor selects None, so its shared Prepared path never
    // enters any import18 Member stage, including the new Source handoff.
    assert!(owner.import18_selection.is_none());
    assert!(!owner.import18_templates.started);
    assert!(!owner.import18_templates.complete);
    assert!(!owner.import18_templates.failed);
    for member in &owner.import18_templates.members {
        assert!(matches!(member.stage, Stage::Unused));
        assert!(member.birth_row.is_none());
    }
    assert!(
        owner
            .import18_templates
            .members
            .iter()
            .all(|member| member.output.partial_data().is_none())
    );
    assert!(owner.authenticate_import18_template_scope_data().is_err());
}

/// Exercises real registration allocations and sticky failure without a Source.
#[cfg(test)]
pub(super) fn assert_projection_members_data(launches: &[PacketNative5SourceLaunch; 3]) {
    let mut templates = Templates::empty();
    templates.started = true;
    templates.failed = true;
    for (index, launch) in launches.iter().enumerate() {
        let member = &mut templates.members[index];
        member.stage = Stage::RegistrationPlan;
        member.mapping_nonce = Some([index as u8 + 1; 32]);
        member.declaration_encoding_row = Some([37, 11, 5]);
        member.declaration_encoding = Some(Vec::with_capacity(37 + index));
        member.registration.begin_data().unwrap();
        let row = registration_plan::Quote::for_launch_data(launch, index).unwrap();
        member.registration_row = Some(row);
        member
            .registration
            .retain_into_data(launch, index, &row, row.requested_storage_data())
            .unwrap();
        // Re-entry poisons the actual completed registration and keeps its banks.
        assert!(member.registration.begin_data().is_err());
        assert!(member.output.partial_data().is_none());
    }

    let observation = templates.observation_data();
    assert!(std::ptr::eq(observation.started, &templates.started));
    assert!(std::ptr::eq(observation.complete, &templates.complete));
    assert!(std::ptr::eq(observation.failed, &templates.failed));
    for (view, member) in observation.members.iter().zip(&templates.members) {
        assert!(std::ptr::eq(view.stage, &member.stage));
        assert!(std::ptr::eq(
            view.registration_row,
            &member.registration_row
        ));
        assert!(std::ptr::eq(view.registration, &member.registration));
        assert!(std::ptr::eq(view.template_row, &member.template_row));
        assert!(std::ptr::eq(view.declaration_row, &member.declaration_row));
        assert!(std::ptr::eq(view.bank_row, &member.bank_row));
        assert!(std::ptr::eq(view.birth_row, &member.birth_row));
        assert!(std::ptr::eq(view.output, &member.output));
        assert!(std::ptr::eq(
            view.declaration_encoding_row,
            &member.declaration_encoding_row
        ));
        assert!(std::ptr::eq(
            view.declaration_encoding,
            &member.declaration_encoding
        ));
        assert!(std::ptr::eq(
            view.initial_projection,
            &member.initial_projection
        ));
        assert!(std::ptr::eq(view.launch_identity, &member.launch_identity));
        assert!(std::ptr::eq(view.mapping_nonce, &member.mapping_nonce));
        assert!(std::ptr::eq(
            view.mapping_lease_data,
            &member.mapping_lease_data
        ));
    }

    let mut expected = Counter::new(usize::MAX);
    templates
        .charge_unprojected_retained_data(&mut expected)
        .unwrap();
    let demand = expected.bytes();
    assert!(demand > 0);
    let mut first = Counter::new(usize::MAX);
    templates.members[0]
        .registration
        .charge_retained_data(&mut first)
        .unwrap();
    let prefix = first.bytes();
    assert!(prefix > 0 && prefix < demand);
    for maximum in [0, prefix - 1, prefix, demand - 1, demand] {
        let mut original = Counter::new(maximum);
        let before = templates.charge_unprojected_retained_data(&mut original);
        let mut projected = Counter::new(maximum);
        let after = templates.charge_retained_data(&mut projected);
        assert_eq!(before.is_ok(), after.is_ok());
        assert_eq!(original.bytes(), projected.bytes());
    }

    let mut after_refusal = Counter::new(demand);
    observation
        .charge_retained_data(&mut after_refusal)
        .unwrap();
    assert_eq!(after_refusal.bytes(), demand);
    assert!(templates.started && templates.failed && !templates.complete);
    for member in &templates.members {
        assert!(matches!(member.stage, Stage::RegistrationPlan));
        assert!(member.registration_row.is_some());
        assert!(member.output.partial_data().is_none());
    }
}
