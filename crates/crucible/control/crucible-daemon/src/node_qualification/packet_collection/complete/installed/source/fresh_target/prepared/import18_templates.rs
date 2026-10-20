//! Constructs real fresh Source templates before archive tickets or native birth.
//!
//! Every step releases all Source loans before the complete Prepared census.
//! Private rows remain in their actual member; neither saved axes nor successful
//! template construction issue an archive, native model or startup permission.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_adapters::cnp::{
    NativeImport18BirthConstructionQuote, OriginalImport18CaptureBankConstructionData,
    OriginalNativeSourceTemplate18Attempt, OriginalNativeSourceTemplate18ConstructionData,
};
use crucible_engine::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::service::complete_restore::import18::PacketNativeImport18Selection;
use std::mem::{size_of, size_of_val};

#[path = "import18_templates/registration_plan.rs"]
mod registration_plan;

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
}

struct Member {
    stage: Stage,
    registration_row: Option<registration_plan::Quote>,
    registration: registration_plan::Attempt,
    template_row: Option<OriginalNativeSourceTemplate18ConstructionData>,
    declaration_row: Option<(usize, usize)>,
    bank_row: Option<OriginalImport18CaptureBankConstructionData>,
    birth_row: Option<NativeImport18BirthConstructionQuote>,
    output: OriginalNativeSourceTemplate18Attempt,
}

impl Member {
    fn empty() -> Self {
        Self {
            stage: Stage::Unused,
            registration_row: None,
            registration: registration_plan::Attempt::empty(),
            template_row: None,
            declaration_row: None,
            bank_row: None,
            birth_row: None,
            output: OriginalNativeSourceTemplate18Attempt::default(),
        }
    }
}

pub(super) struct Templates {
    started: bool,
    complete: bool,
    failed: bool,
    members: [Member; 3],
}

impl Templates {
    pub(super) fn empty() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            members: std::array::from_fn(|_| Member::empty()),
        }
    }

    /// Counts every partial actual output, including failed declaration/banks.
    pub(super) fn charge_retained_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        // The enclosing Option<Prepared> already prices all inline rows/flags.
        for member in &self.members {
            member.registration.charge_retained_data(counter)?;
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
        OriginalNativeSourceTemplate18Attempt::retained_counter_scratch_data()
            + registration_plan::Attempt::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&mut Counter>()
            + size_of::<std::slice::Iter<'static, Member>>()
            + size_of::<&Member>()
            + size_of::<usize>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), QualificationError>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl PreparedCompleteRestoration {
    /// Checks only genuine installed code custody before each fresh operation.
    fn authenticate_import18_template_scope_data(&self) -> Result<Import18Selection, RuntimeError> {
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
    fn observe_import18_templates_data(&self, demand: [usize; 3]) -> Result<(), RuntimeError> {
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
        self.import18_templates.started = true;
        self.import18_templates.failed = true;
        self.authenticate_import18_template_scope_data()?;
        let maximum = usize::try_from(self.selected.resources.memory_bytes.get())
            .map_err(|_| RuntimeError::ResourceLimit)?;

        for selected in 0..3 {
            self.prepare_import18_member_data(selected, maximum)?;
        }
        self.observe_import18_templates_data([0; 3])?;
        self.import18_templates.complete = true;
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
        self.import18_templates.members[selected].stage = Stage::RegistrationPlan;
        self.import18_templates.members[selected]
            .registration
            .begin_data()?;
        self.observe_import18_templates_data([0; 3])?;
        let row = registration_plan::Quote::for_launch_data(&self.launches[selected], selected)?;
        self.import18_templates.members[selected].registration_row = Some(row);
        self.observe_import18_templates_data(row.requested_storage_data())?;
        let result = self.import18_templates.members[selected]
            .registration
            .retain_into_data(
                &self.launches[selected],
                selected,
                &row,
                row.requested_storage_data(),
            );
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;

        // No clone or Rc follows an arbitrary source argument. The input comes
        // directly from this same admitted code authority's fixed roster slot.
        self.observe_import18_templates_data([0; 3])?;
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
        let result = self.code_authority.roster().sources[selected].native_source_template18_into(
            &row,
            &mut self.import18_templates.members[selected].output,
        );
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;

        self.observe_import18_templates_data([0; 3])?;
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
            .bind_native_import18_declaration_data(selection, &self.launches[selected]);
        let observed = self.observe_import18_templates_data([0; 3]);
        result.and(observed)?;

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
            .native_import18_birth_initialize_quote_data(&self.launches[selected], maximum)?;
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
            &self.launches[selected],
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

    fn import18_template_counter_scratch_data() -> Result<usize, RuntimeError> {
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
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

/// Uses the actual admitted fixture, never a fabricated graph/plan/native owner.
#[cfg(test)]
pub(super) fn assert_actual_code_custody_data(owner: &PreparedCompleteRestoration) {
    registration_plan::assert_actual_launch_data(&owner.launches[0]);
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
