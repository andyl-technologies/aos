//! Constructs a retained registrar under the same original bootstrap and cut.

use super::super::{OriginalImport18RawBootstrap, private_body_owner_counter_scratch_data};
use super::{construction_data, counter_scratch_data};
use crate::ProviderError;
use crate::handshake::{ExtensionHandshake, ExtensionOfferV1};
use std::mem::size_of;

/// Separately admits quote work, actual construction and the surviving owner.
pub(in super::super::super) trait OriginalImport18HelloRegistrarAdmission {
    /// Admits fixed quote controls under original enclosing custody.
    ///
    /// # Errors
    /// Refuses stale custody, missing original credit or incomplete accounting.
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError>;

    /// Admits the actual stored row before configuration cloning or shared allocation.
    ///
    /// # Errors
    /// Refuses stale custody, short original credit or incomplete whole-owner demand.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes every surviving registrar owner after either constructor outcome.
    ///
    /// # Errors
    /// Refuses stale custody, incomplete census or whole-owner demand above credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual_backing: usize,
    ) -> Result<(), ProviderError>;
}

impl OriginalImport18RawBootstrap {
    /// Constructs the fresh unadmitted registrar once after original request checks.
    ///
    /// The physical attempt exists before the first private read. Its original
    /// initial row separately funds quote controls and this stored constructor
    /// row; neither an announced number nor this DATA transition grants funding.
    ///
    /// # Errors
    /// Refuses re-entry, original input/cut failure, admission, construction,
    /// actual retained census or any terminal guard.
    pub(in super::super::super) fn construct_hello_registrar_data(
        &mut self,
        admission: &dyn OriginalImport18HelloRegistrarAdmission,
    ) -> Result<(), ProviderError> {
        self.hello_registrar.start_data(self.cut)?;
        let outcome = self.construct_current_hello_registrar(admission);
        let terminal = self.guard_hello_registrar_inputs();
        match outcome.and(terminal) {
            Ok(()) => self.hello_registrar.complete_data(),
            Err(error) => {
                self.hello_registrar.refuse_data();
                Err(error)
            }
        }
    }

    fn guard_hello_registrar_inputs(&self) -> Result<(), ProviderError> {
        self.with_hello_request_data(|_, _| Ok(()))?;
        Ok(())
    }

    fn construct_current_hello_registrar(
        &mut self,
        admission: &dyn OriginalImport18HelloRegistrarAdmission,
    ) -> Result<(), ProviderError> {
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        self.guard_hello_registrar_inputs()?;
        admission.quote_data(self, counter_scratch_data())?;
        self.guard_hello_registrar_inputs()?;
        let row = construction_data(
            self.typed_bodies_data()?.launch.launch_data(),
            self.bounds.requested_peak,
        )?;
        self.hello_registrar.quote_data(row)?;
        admission.construct_data(self, row)?;

        let outcome = self.construct_guarded_hello_registrar();
        let terminal = self
            .hello_registrar
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal
    }

    fn construct_guarded_hello_registrar(&mut self) -> Result<(), ProviderError> {
        self.guard_hello_registrar_inputs()?;
        let cut = self.cut;
        let Self {
            parsed,
            hello_selection,
            hello_registrar,
            ..
        } = self;
        let launch = parsed.bodies_data()?.launch.launch_data();
        let outcome = hello_registrar.construct_data(
            launch,
            hello_selection.as_ref().ok_or_else(refused)?,
            cut,
        );
        let terminal = self.guard_hello_registrar_inputs();
        outcome?;
        terminal
    }

    /// Lends the same completed unselected wrapper while original guards hold.
    ///
    /// The caller independently admits callback work. Only Copy DATA returns;
    /// this immutable loan creates no connection, reply, ACK or native policy.
    ///
    /// # Errors
    /// Refuses incomplete/refused construction, stale custody, callback failure
    /// or any terminal guard after the callback, including an error callback.
    pub(in super::super::super) fn with_hello_registrar_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&ExtensionHandshake) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.guard_hello_registrar_inputs()?;
        let wrapper = self.hello_registrar.data(self.cut)?;
        let outcome = inspect(wrapper);
        let terminal = self
            .guard_hello_registrar_inputs()
            .and_then(|()| self.hello_registrar.data(self.cut).map(|_| ()));
        let output = outcome?;
        terminal?;
        Ok(output)
    }

    /// Names the completed registrar loan and its original input guards.
    ///
    /// This loan does not repeat configuration cloning, validation or shared
    /// allocation. Subsequent constructors fund their own operations separately.
    pub(in super::super::super) fn hello_registrar_loan_counter_scratch_data<R: Copy>() -> usize {
        super::super::hello_request::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&super::Attempt>()
            + size_of::<crate::protocol_snapshot::ProtocolCaptureOwner>()
            + size_of::<crate::operational_time::OperationalDeadline>()
            + size_of::<Option<crate::operational_time::OperationalDeadline>>()
            + size_of::<&ExtensionHandshake>()
            + size_of::<Option<&ExtensionHandshake>>()
            + size_of::<Result<&ExtensionHandshake, ProviderError>>()
            + size_of::<R>() * 2
            + size_of::<Result<R, ProviderError>>() * 2
            + size_of::<Result<(), ProviderError>>() * 3
    }
}

/// Names only actual original input/loan guards and admission wrapper controls.
pub(super) fn counter_scratch_data_native() -> usize {
    OriginalImport18RawBootstrap::hello_value_loan_counter_scratch_data::<()>()
        + OriginalImport18RawBootstrap::hello_selection_loan_counter_scratch_data::<()>()
        + private_body_owner_counter_scratch_data()
        + size_of::<super::super::hello_request::Claims>()
        + size_of::<&ExtensionOfferV1>()
        + size_of::<&ExtensionHandshake>()
        + size_of::<&dyn OriginalImport18HelloRegistrarAdmission>()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<usize>() * 4
        + size_of::<Result<(), ProviderError>>() * 5
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 registrar admission refused")
}
