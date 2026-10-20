//! Retains actual planned Hello18 inputs before fresh Source construction.
//!
//! The same Prepared member roots this once attempt, quote and all partials.
//! The real caller authenticates installed code custody and admits all three
//! axes before construction. These names grant no Source, Initial or Recipe.

use super::*;
use crucible_engine::node_adapters::cnp::PacketCompleteAckHostRegistrationPlan;
use crucible_node_format::{ContractError, Id, IdSet};
use crucible_node_transport::ProviderError;
use crucible_node_transport::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, native_import18_hello_declaration_data,
};

const PRIVATE_LAUNCHES: [&str; 3] = [
    "installed-complete-boot-0",
    "installed-complete-boot-1",
    "installed-complete-boot-2",
];
const CONNECTIONS: [&str; 3] = [
    "installed-complete-connection-0",
    "installed-complete-connection-1",
    "installed-complete-connection-2",
];

type Names = (IdSet, Vec<String>);

/// Binds a row to the actual declaration and one fixed Prepared member.
#[derive(Clone, Copy)]
pub(super) struct Quote {
    declaration: PacketNativeImport18HelloDeclarationData,
    member: usize,
    requested: [usize; 3],
}

impl Quote {
    /// Derives the exact row from this member's actual native declaration.
    ///
    /// # Errors
    /// Refuses unsupported launch selectors, an absent member or checked overflow.
    pub(super) fn for_launch_data(
        launch: &PacketNative5SourceLaunch,
        member: usize,
    ) -> Result<Self, RuntimeError> {
        let declaration = native_import18_hello_declaration_data(launch)
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        let private = PRIVATE_LAUNCHES
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let connection = CONNECTIONS
            .get(member)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let [retained, transient, scratch] = declaration
            .registration_names_construction_storage_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        Ok(Self {
            declaration,
            member,
            requested: [
                retained
                    .checked_add(private.len())
                    .and_then(|bytes| bytes.checked_add(connection.len()))
                    .ok_or(RuntimeError::ResourceLimit)?,
                transient
                    .checked_add(Attempt::constructor_transient_data())
                    .ok_or(RuntimeError::ResourceLimit)?,
                scratch
                    .checked_add(Attempt::local_counter_scratch_data())
                    .ok_or(RuntimeError::ResourceLimit)?,
            ],
        })
    }

    /// Returns the additional retained, transient and fixed-scratch axes.
    pub(super) fn requested_storage_data(&self) -> [usize; 3] {
        self.requested
    }
}

/// Owns the spent attempt and the same original allocations through refusal.
pub(super) struct Attempt {
    started: bool,
    construction_entered: bool,
    failed: bool,
    complete: bool,
    source_transfer_started: bool,
    source_transfer_complete: bool,
    private_launch: Option<Id>,
    connection: Option<Id>,
    names: Option<Names>,
    registration: Option<PacketCompleteAckHostRegistrationPlan>,
}

impl Attempt {
    /// Creates an unentered retained destination without allocation.
    pub(super) fn empty() -> Self {
        Self {
            started: false,
            construction_entered: false,
            failed: false,
            complete: false,
            source_transfer_started: false,
            source_transfer_complete: false,
            private_launch: None,
            connection: None,
            names: None,
            registration: None,
        }
    }

    /// Spends the enclosing actual slot before quote/prewalk and all effects.
    ///
    /// # Errors
    /// Refuses repeated entry while retaining and poisoning the same output.
    pub(super) fn begin_data(&mut self) -> Result<(), RuntimeError> {
        if self.started {
            self.failed = true;
            return Err(RuntimeError::DuplicateOperation);
        }
        self.started = true;
        self.failed = true;
        Ok(())
    }

    /// Consumes only a same-operand row after the caller's actual admission.
    ///
    /// `admitted` describes this private caller's checked additional axes; it is
    /// not an Initial allowance or a capability. All checks precede allocation.
    ///
    /// # Errors
    /// Refuses spent or occupied output, changed operands, insufficient admitted
    /// axes, allocation failure or a changed defining fixed identifier.
    pub(super) fn retain_into_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        member: usize,
        quote: &Quote,
        admitted: [usize; 3],
    ) -> Result<(), RuntimeError> {
        if !self.started
            || self.construction_entered
            || !self.failed
            || self.complete
            || self.private_launch.is_some()
            || self.connection.is_some()
            || self.names.is_some()
            || self.registration.is_some()
        {
            self.started = true;
            self.construction_entered = true;
            self.failed = true;
            return Err(RuntimeError::DuplicateOperation);
        }
        self.construction_entered = true;
        let actual = Quote::for_launch_data(launch, member)?;
        if member != quote.member
            || actual.declaration != quote.declaration
            || actual.requested != quote.requested
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for (requested, available) in quote.requested.into_iter().zip(admitted) {
            if requested > available {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        self.private_launch =
            Some(Id::new(PRIVATE_LAUNCHES[member]).map_err(|_| RuntimeError::UnsupportedFacet)?);
        self.connection =
            Some(Id::new(CONNECTIONS[member]).map_err(|_| RuntimeError::UnsupportedFacet)?);
        quote
            .declaration
            .retain_registration_names_into_data(&mut self.names)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.finish_names_data()?;
        self.complete = true;
        self.failed = false;
        Ok(())
    }

    /// Moves the same planned inputs into the quoted actual fresh Source once.
    ///
    /// The caller retains the Source quote and independently admits the whole
    /// current Prepared plus additional R/T/S before entering this handoff.
    ///
    /// # Errors
    /// Refuses repeated or incomplete input custody, a foreign Source quote or
    /// any failed Source allocation/authentication. Every remaining input stays
    /// here or in that same Source's retained failed worker.
    pub(super) fn retain_source_initialize_into_data(
        &mut self,
        source: &mut PacketCompleteSemanticSource,
        launch: &PacketNative5SourceLaunch,
        quote: &NativeImport18BirthConstructionQuote,
    ) -> Result<(), RuntimeError> {
        if self.source_transfer_started {
            self.failed = true;
            return Err(RuntimeError::DuplicateOperation);
        }
        self.source_transfer_started = true;
        let complete = self.started
            && !self.failed
            && self.complete
            && self.private_launch.is_some()
            && self.registration.is_some();
        self.failed = true;
        if !complete {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let result = source.retain_native_import18_birth_initialize_into_data(
            launch,
            &mut self.private_launch,
            &mut self.registration,
            quote,
        );
        if result.is_ok() {
            self.source_transfer_complete = true;
            self.failed = false;
        }
        result
    }

    /// Exports the same original planned inputs through the selected Source once.
    ///
    /// The real workspace and input are reserved before this synchronous loan;
    /// all remaining names stay here or in that Source's failed association.
    pub(super) fn retain_source_derivation_into<'a>(
        &mut self,
        source: &'a mut PacketCompleteSemanticSource,
        launch: &'a PacketNative5SourceLaunch,
        job: &mut crucible_engine::node_adapters::cnp::source_birth_derivation::job::SourceBirthDerivationJob,
        workspace: crucible_engine::node_adapters::cnp::source_birth_derivation::request_wire::ExportWorkspace<'a>,
    ) -> Result<(), RuntimeError> {
        if self.source_transfer_started {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.source_transfer_started = true;
        let ready = self.started
            && !self.failed
            && self.complete
            && self.private_launch.is_some()
            && self.registration.is_some();
        self.failed = true;
        if !ready {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let result = source.export_native_import18_derivation_into(
            launch,
            &mut self.private_launch,
            &mut self.registration,
            job,
            workspace,
        );
        if result.is_ok() {
            self.source_transfer_complete = true;
            self.failed = false;
        }
        result
    }

    /// Moves the same vector/string/Id backing into the final planned object.
    fn finish_names_data(&mut self) -> Result<(), RuntimeError> {
        if self.registration.is_some() {
            self.failed = true;
            return Err(RuntimeError::DuplicateOperation);
        }
        match (self.connection.take(), self.names.take()) {
            (Some(connection_id), Some((features, envelope_extensions))) => {
                self.registration = Some(PacketCompleteAckHostRegistrationPlan {
                    connection_id,
                    features,
                    extensions: Vec::new(),
                    envelope_extensions,
                });
                Ok(())
            }
            (connection, names) => {
                self.connection = connection;
                self.names = names;
                Err(RuntimeError::OwnerUnavailable)
            }
        }
    }

    /// Counts all actual capacity, including refused and partially built names.
    ///
    /// # Errors
    /// Refuses checked backing overflow or the actual counter's remaining limit.
    pub(super) fn charge_retained_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        self.charge_owned_data(counter)
            .map_err(|_| RuntimeError::ResourceLimit)
    }

    fn charge_owned_data(&self, counter: &mut Counter) -> Result<(), QualificationError> {
        counter.charge(&self.private_launch)?;
        counter.charge(&self.connection)?;
        counter.charge(&self.names)?;
        if let Some(plan) = &self.registration {
            counter.charge(&plan.connection_id)?;
            counter.charge(&plan.features)?;
            counter.charge(&plan.envelope_extensions)?;
            // This private owner creates extensions only with Vec::new()
            // and exposes no mutable plan. Its vector has no allocation.
        }
        Ok(())
    }

    fn constructor_transient_data() -> usize {
        size_of::<PacketCompleteAckHostRegistrationPlan>()
            + size_of::<Vec<crucible_node_format::ExtensionSelection>>()
            + size_of::<Option<PacketCompleteAckHostRegistrationPlan>>()
            + size_of::<(Option<Id>, Option<Names>)>()
            + size_of::<Id>() * 2
            + size_of::<Option<Id>>() * 2
            + size_of::<String>()
            + size_of::<Vec<u8>>()
            + size_of::<Result<Id, ContractError>>()
            + size_of::<Result<Id, crucible_node_format::IdFromOwnedError>>()
            + crucible_node_format::IdFromOwnedError::construction_transient_bytes_data()
            + crucible_node_format::IdFromOwnedError::construction_counter_scratch_bytes_data()
    }

    fn local_counter_scratch_data() -> usize {
        Self::retained_counter_scratch_data()
            + size_of::<Quote>() * 2
            + size_of::<Result<Quote, RuntimeError>>() * 2
            + size_of::<&Quote>()
            + size_of::<&Attempt>()
            + size_of::<&mut Attempt>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&mut Counter>()
            + size_of::<&Option<Id>>() * 2
            + size_of::<Option<&Id>>() * 2
            + size_of::<&Id>()
            + size_of::<&Option<Names>>()
            + size_of::<Option<&Names>>()
            + size_of::<&Names>()
            + size_of::<&Vec<Id>>()
            + size_of::<&Vec<String>>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<std::slice::Iter<'static, String>>()
            + size_of::<&String>()
            + size_of::<&PacketCompleteAckHostRegistrationPlan>()
            + size_of::<Option<&PacketCompleteAckHostRegistrationPlan>>()
            + size_of::<
                std::iter::Zip<std::array::IntoIter<usize, 3>, std::array::IntoIter<usize, 3>>,
            >()
            + size_of::<Option<(usize, usize)>>()
            + size_of::<(usize, usize)>()
            + size_of::<[usize; 3]>() * 3
            + size_of::<&[usize; 3]>() * 2
            + size_of::<Option<&&'static str>>() * 2
            + size_of::<Result<&&'static str, RuntimeError>>() * 2
            + size_of::<&&str>() * 2
            + size_of::<usize>() * 7
            + size_of::<Option<usize>>()
            + size_of::<Result<(), RuntimeError>>() * 3
            + size_of::<Result<(), QualificationError>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
    }

    /// Prices the actual longest nested observer control chain independently.
    fn retained_counter_scratch_data() -> usize {
        // charge_retained -> charge_owned -> Counter::charge -> Option::charge
        // -> tuple::charge -> Vec::charge -> leaf::charge -> Counter::add.
        // Each receiver/result is a separate live method role, even though all
        // mutable Counter loans designate the same allocation-free observer.
        size_of::<&mut Counter>() * 8
            + size_of::<Result<(), QualificationError>>() * 8
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<&Attempt>() * 2
            + size_of::<&Option<Names>>() * 2
            + size_of::<Option<&Names>>()
            + size_of::<&Names>() * 2
            + size_of::<&Vec<Id>>()
            + size_of::<&Vec<String>>()
            + size_of::<std::slice::Iter<'static, Id>>()
            + size_of::<std::slice::Iter<'static, String>>()
            + size_of::<Option<&Id>>()
            + size_of::<Option<&String>>()
            + size_of::<&Id>()
            + size_of::<&String>()
            + size_of::<usize>() * 4
            + size_of::<Option<usize>>() * 2
    }

    fn source_transfer_counter_scratch_data() -> usize {
        size_of::<&mut Attempt>()
            + size_of::<&mut PacketCompleteSemanticSource>()
            + size_of::<&PacketNative5SourceLaunch>()
            + size_of::<&NativeImport18BirthConstructionQuote>()
            + size_of::<&mut Option<Id>>()
            + size_of::<&mut Option<PacketCompleteAckHostRegistrationPlan>>()
            + size_of::<bool>()
            + size_of::<Result<(), RuntimeError>>() * 2
    }

    /// Names the constructor, declaration and nested retained-observer controls.
    pub(super) fn counter_scratch_data() -> usize {
        Self::local_counter_scratch_data()
            + Self::source_transfer_counter_scratch_data()
            + PacketNativeImport18HelloDeclarationData::registration_names_counter_scratch_data()
    }
}

/// Checks the scoped constructor against an actual retained fixture launch.
///
/// # Panics
/// Panics when the defining row, once guards, custody or census control differs.
#[cfg(test)]
pub(super) fn assert_actual_launch_data(launch: &PacketNative5SourceLaunch) {
    let row = Quote::for_launch_data(launch, 0).unwrap();
    for axis in 0..3 {
        let mut attempt = Attempt::empty();
        attempt.begin_data().unwrap();
        let mut admitted = row.requested_storage_data();
        admitted[axis] = admitted[axis].checked_sub(1).unwrap();
        assert!(attempt.retain_into_data(launch, 0, &row, admitted).is_err());
        assert!(attempt.started && attempt.failed && !attempt.complete);
        assert!(attempt.private_launch.is_none());
        assert!(attempt.connection.is_none());
        assert!(attempt.names.is_none());
        assert!(attempt.registration.is_none());
        assert!(
            attempt
                .retain_into_data(launch, 0, &row, row.requested_storage_data())
                .is_err()
        );
        assert!(attempt.private_launch.is_none() && attempt.registration.is_none());
    }
    let mut foreign = Attempt::empty();
    foreign.begin_data().unwrap();
    assert!(
        foreign
            .retain_into_data(launch, 1, &row, row.requested_storage_data())
            .is_err()
    );
    assert!(foreign.failed && foreign.private_launch.is_none());

    let mut attempt = Attempt::empty();
    attempt.begin_data().unwrap();
    attempt
        .retain_into_data(launch, 0, &row, row.requested_storage_data())
        .unwrap();
    assert!(attempt.complete && !attempt.failed);
    assert_eq!(
        attempt.private_launch.as_ref().unwrap().as_str(),
        PRIVATE_LAUNCHES[0]
    );
    let plan = attempt.registration.as_ref().unwrap();
    assert_eq!(plan.connection_id.as_str(), CONNECTIONS[0]);
    assert!(plan.features.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        plan.envelope_extensions
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(plan.extensions.is_empty() && plan.extensions.capacity() == 0);
    let features = plan.features.as_ptr();
    let envelope = plan.envelope_extensions.as_ptr();
    let connection = plan.connection_id.as_str().as_ptr();
    let mut counter = Counter::new(usize::MAX);
    attempt.charge_retained_data(&mut counter).unwrap();
    assert_eq!(counter.bytes(), row.requested[0]);
    assert!(attempt.begin_data().is_err());
    assert!(attempt.failed);
    let plan = attempt.registration.as_ref().unwrap();
    assert_eq!(features, plan.features.as_ptr());
    assert_eq!(envelope, plan.envelope_extensions.as_ptr());
    assert_eq!(connection, plan.connection_id.as_str().as_ptr());

    let mut moved = Attempt::empty();
    moved.begin_data().unwrap();
    moved.connection = Some(Id::new(CONNECTIONS[0]).unwrap());
    row.declaration
        .retain_registration_names_into_data(&mut moved.names)
        .unwrap();
    let (features, envelope) = moved.names.as_ref().unwrap();
    let features_address = features.as_ptr();
    let envelope_address = envelope.as_ptr();
    let first_key_address = envelope[0].as_ptr();
    let connection_address = moved.connection.as_ref().unwrap().as_str().as_ptr();
    moved.finish_names_data().unwrap();
    let plan = moved.registration.as_ref().unwrap();
    assert_eq!(features_address, plan.features.as_ptr());
    assert_eq!(envelope_address, plan.envelope_extensions.as_ptr());
    assert_eq!(first_key_address, plan.envelope_extensions[0].as_ptr());
    assert_eq!(connection_address, plan.connection_id.as_str().as_ptr());

    // A missing second input restores the first instead of dropping its bank.
    let mut partial = Attempt::empty();
    partial.begin_data().unwrap();
    partial.connection = Some(Id::new(CONNECTIONS[0]).unwrap());
    let address = partial.connection.as_ref().unwrap().as_str().as_ptr();
    assert!(partial.finish_names_data().is_err());
    assert_eq!(
        address,
        partial.connection.as_ref().unwrap().as_str().as_ptr()
    );
    let mut counter = Counter::new(usize::MAX);
    partial.charge_retained_data(&mut counter).unwrap();
    assert_eq!(counter.bytes(), CONNECTIONS[0].len());
}
