//! Joins an actual received startup16 owner to its published first Observe.
//!
//! This private witness carries the existing live released-world witness and
//! the same MAC-verified once attempt. It grants no receive, model, input,
//! execution or Capture permission. Future actions require separately admitted
//! current proofs and a Source/Core issuer; the Endpoint remains closed here.

use super::*;
use std::mem::size_of;

/// Retains exact native provenance after the first signed Observe is published.
///
/// Its fields cannot be constructed from a scope DTO or a success boolean.
/// No Clone implementation or private-scope reconstruction is provided.
pub(crate) struct OriginalRestoredSuffixPostObservation {
    released: OriginalRestorationReleased,
    attempt: Rc<RefCell<NativeRestorationObservationAttempt>>,
    record: usize,
}

pub(super) fn retain_published_suffix_observation_data<S: ProviderStream>(
    permit: &OriginalRestorationObservationPermit,
    connection: &Connection<S>,
    control: &PacketControl,
    records: &[ExchangeRecord],
) -> Result<(), ProviderError> {
    {
        let owner = permit
            .read
            .released
            .boot
            .try_borrow()
            .map_err(|_| borrowed())?;
        let Some(state) = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
        else {
            return Ok(());
        };
        let flight = permit.read.attempt.try_borrow().map_err(|_| borrowed())?;
        state.authenticate_witness_storage_data(
            &flight
                .artifact
                .as_ref()
                .ok_or_else(refused)?
                .request,
        )?;
    }
    {
        let mut owner = permit
            .read
            .released
            .boot
            .try_borrow_mut()
            .map_err(|_| borrowed())?;
        owner
            .startup
            .as_mut()
            .and_then(|startup| startup.restored_suffix.as_mut())
            .ok_or_else(refused)?
            .begin_observation_publication_data()?;
    }
    authenticate_suffix_selection_data(connection)?;
    permit
        .read
        .released
        .authenticate_current_data(connection, control, records)?;
    let record = records.len().checked_sub(1).ok_or_else(refused)?;
    authenticate_published_data(
        &permit.read.released,
        &permit.read.attempt,
        record,
        connection,
        control,
        records,
    )?;
    let mut owner = permit
        .read
        .released
        .boot
        .try_borrow_mut()
        .map_err(|_| borrowed())?;
    owner.authenticate_original_invocation_prepare_target_data()?;
    // Old lanes retain their exact once-Observe behavior. Only an actual
    // installed startup16 owner can acquire the additional private link.
    if let Some(state) = owner
        .startup
        .as_mut()
        .and_then(|startup| startup.restored_suffix.as_mut())
    {
        state.publish_observation_data(&permit.read.attempt, record)?;
    }
    Ok(())
}

impl NativeAckBoot {
    /// Borrows genuine startup16, Commit, World and first-observation provenance.
    ///
    /// # Errors
    /// Refuses old lanes, unsealed geometry, incomplete or foreign first
    /// publication, changed connection/Control or poisoned reservation custody.
    pub(crate) fn original_restored_suffix_post_observation_data<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<OriginalRestoredSuffixPostObservation, ProviderError> {
        {
            let owner = boot.try_borrow().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_ref()
                .and_then(|startup| startup.restored_suffix.as_ref())
                .ok_or_else(refused)?;
            let flight = owner
                .restoration_observation
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| borrowed())?;
            state.authenticate_witness_storage_data(
                &flight
                    .artifact
                    .as_ref()
                    .ok_or_else(refused)?
                    .request,
            )?;
        }
        authenticate_suffix_selection_data(connection)?;
        let released =
            match Self::original_restoration_release_data(boot, connection, control, records)? {
                OriginalRestorationReleaseState::Released(released) => released,
                OriginalRestorationReleaseState::Pending => return Err(refused()),
            };
        let owner = boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let state = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?;
        state.reservation_data()?;
        let attempt = Rc::clone(owner.restoration_observation.as_ref().ok_or_else(refused)?);
        let flight = attempt.try_borrow().map_err(|_| borrowed())?;
        let terminal = flight.terminal.as_ref().ok_or_else(refused)?;
        let mut matched = None;
        for (index, record) in records.iter().enumerate() {
            if record.originals().last() == Some(terminal) && matched.replace(index).is_some() {
                return Err(refused());
            }
        }
        let record = matched.ok_or_else(refused)?;
        state.authenticate_observation_data(&attempt, record)?;
        drop(flight);
        drop(owner);
        let witness = OriginalRestoredSuffixPostObservation {
            released,
            attempt,
            record,
        };
        witness.authenticate_current_data(connection, control, records)?;
        Ok(witness)
    }
}

impl OriginalRestoredSuffixPostObservation {
    /// Reauthenticates the same actual native owners and complete sent prefix.
    ///
    /// This initial-checkpoint witness deliberately retains the old released
    /// currentness checks. It does not assert future freshness after progress.
    ///
    /// # Errors
    /// Refuses changed live owners, stale scope, partial publication or a
    /// different received reservation/first-observation association.
    pub(crate) fn authenticate_current_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        {
            let owner = self.released.boot.try_borrow().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_ref()
                .and_then(|startup| startup.restored_suffix.as_ref())
                .ok_or_else(refused)?;
            let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
            state.authenticate_witness_storage_data(
                &flight
                    .artifact
                    .as_ref()
                    .ok_or_else(refused)?
                    .request,
            )?;
        }
        authenticate_suffix_selection_data(connection)?;
        self.released
            .authenticate_current_data(connection, control, records)?;
        authenticate_published_data(
            &self.released,
            &self.attempt,
            self.record,
            connection,
            control,
            records,
        )?;
        let owner = self.released.boot.try_borrow().map_err(|_| borrowed())?;
        let state = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?;
        state.authenticate_observation_data(&self.attempt, self.record)
    }
}

fn authenticate_published_data<S: ProviderStream>(
    released: &OriginalRestorationReleased,
    attempt: &Rc<RefCell<NativeRestorationObservationAttempt>>,
    record: usize,
    connection: &Connection<S>,
    control: &PacketControl,
    records: &[ExchangeRecord],
) -> Result<(), ProviderError> {
    let owner = released.boot.try_borrow().map_err(|_| borrowed())?;
    owner.authenticate_original_invocation_prepare_target_data()?;
    if owner
        .restoration_observation
        .as_ref()
        .is_none_or(|actual| !Rc::ptr_eq(actual, attempt))
    {
        return Err(refused());
    }
    let flight = attempt.try_borrow().map_err(|_| borrowed())?;
    flight.authenticate_published_suffix_milestones_data()?;
    let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
    let context = flight.context.as_ref().ok_or_else(refused)?;
    let original = flight.original.as_ref().ok_or_else(refused)?;
    let terminal = flight.terminal.as_ref().ok_or_else(refused)?;
    let world = released.world.try_borrow().map_err(|_| borrowed())?;
    if context.request != artifact.request
        || artifact.request.scope != world.artifact.as_ref().ok_or_else(refused)?.request.scope
    {
        return Err(refused());
    }
    artifact
        .request
        .authenticate_body_data(flight.body.as_ref().ok_or_else(refused)?)?;
    let exchange = records.get(record).ok_or_else(refused)?;
    if exchange.sent() != exchange.originals().len()
        || exchange.originals().last() != Some(terminal)
    {
        return Err(refused());
    }
    control.authenticate_original_restoration_observation_terminal_data(original, terminal)?;
    for index in 0..exchange.originals().len() {
        exchange.original_sent_frame(connection, index)?;
    }
    Ok(())
}

pub(crate) fn original_restored_suffix_post_observation_counter_scratch_data() -> usize {
    use super::super::super::super::native_startup::OriginalNativeStartupBoot as StartupOwner;
    use super::super::super::super::restored_suffix::NativeRestoredSuffixStartupOwner as SuffixOwner;

    let owner_loans = size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, ProviderError>>()
        + size_of::<std::cell::RefMut<'static, NativeAckBoot>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeAckBoot>, std::cell::BorrowMutError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeAckBoot>, ProviderError>>()
        + size_of::<
            Result<std::cell::Ref<'static, NativeRestorationObservationAttempt>, ProviderError>,
        >()
        + size_of::<std::cell::Ref<'static, NativeRestorationActivationAttempt>>()
        + size_of::<
            Result<
                std::cell::Ref<'static, NativeRestorationActivationAttempt>,
                std::cell::BorrowError,
            >,
        >()
        + size_of::<
            Result<std::cell::Ref<'static, NativeRestorationActivationAttempt>, ProviderError>,
        >()
        + size_of::<Option<&Rc<RefCell<NativeRestorationObservationAttempt>>>>()
        + size_of::<Result<&Rc<RefCell<NativeRestorationObservationAttempt>>, ProviderError>>()
        + size_of::<Option<&StartupOwner>>()
        + size_of::<Option<&mut StartupOwner>>()
        + size_of::<Option<&Box<SuffixOwner>>>()
        + size_of::<Option<&mut Box<SuffixOwner>>>()
        + size_of::<Result<&Box<SuffixOwner>, ProviderError>>()
        + size_of::<Result<&mut Box<SuffixOwner>, ProviderError>>();
    let typed_loans = size_of::<Option<&Envelope>>()
        + size_of::<&Envelope>()
        + size_of::<Result<&Envelope, ProviderError>>()
        + size_of::<Option<&PacketRestorationObservationArtifact>>()
        + size_of::<Result<&PacketRestorationObservationArtifact, ProviderError>>()
        + size_of::<Option<&PacketRestorationObservationContext>>()
        + size_of::<Result<&PacketRestorationObservationContext, ProviderError>>()
        + size_of::<Option<&crate::bodies::ObserveRequest>>()
        + size_of::<Result<&crate::bodies::ObserveRequest, ProviderError>>()
        + size_of::<Option<&PacketRestorationActivationArtifact>>()
        + size_of::<Result<&PacketRestorationActivationArtifact, ProviderError>>();
    let record_views = size_of::<OriginalRestorationReleased>()
        + size_of::<&ExchangeRecord>()
        + size_of::<Result<&ExchangeRecord, ProviderError>>()
        + size_of::<Option<(usize, &ExchangeRecord)>>()
        + size_of::<crate::connection::OriginalSentFrameView<'static>>()
        + size_of::<Result<crate::connection::OriginalSentFrameView<'static>, ProviderError>>();
    let live_owner_views = size_of::<OriginalRestoredSuffixPostObservation>()
        + size_of::<Result<OriginalRestoredSuffixPostObservation, ProviderError>>()
        + size_of::<OriginalRestorationReleaseState>()
        + size_of::<Result<OriginalRestorationReleaseState, ProviderError>>()
        + size_of::<&OriginalRestorationReleased>()
        + size_of::<&OriginalRestorationObservationPermit>()
        + size_of::<&Rc<RefCell<NativeRestorationObservationAttempt>>>()
        + size_of::<std::cell::Ref<'static, NativeRestorationObservationAttempt>>()
        + size_of::<
            Result<
                std::cell::Ref<'static, NativeRestorationObservationAttempt>,
                std::cell::BorrowError,
            >,
        >()
        + size_of::<std::cell::Ref<'static, NativeAckBoot>>()
        + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, std::cell::BorrowError>>()
        + size_of::<&[ExchangeRecord]>()
        + size_of::<std::slice::Iter<'static, ExchangeRecord>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, ExchangeRecord>>>();

    let prefix_and_admission_views = size_of::<(usize, &ExchangeRecord)>()
        + size_of::<Option<&ExchangeRecord>>()
        + size_of::<Option<usize>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<&crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission>(
        )
        + size_of::<
            Result<
                &crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission,
                ProviderError,
            >,
        >()
        + size_of::<&crate::reference_packet::control::PacketControlSelection>()
        + size_of::<&crate::handshake::ConnectionAuthority>()
        + size_of::<&[crucible_node_contract::SchemaRef]>();

    let selected_contract_views = size_of::<std::slice::Iter<'static, crucible_node_contract::SchemaRef>>()
        + size_of::<Option<&crucible_node_contract::SchemaRef>>()
        + size_of::<Result<&crucible_node_contract::SchemaRef, ProviderError>>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::NodeBinding>>()
        + size_of::<std::slice::Iter<'static, crucible_node_contract::Id>>() * 2
        + size_of::<&crucible_node_contract::NodeBinding>()
        + size_of::<&crucible_node_contract::Id>()
        + size_of::<&crucible_node_contract::SchemaRef>()
        + size_of::<&str>()
        + crate::reference_packet::service::native_startup::restoration_suffix_schema_counter_scratch_data()
        + crate::reference_packet::service::complete_restore::restoration_observe::restoration_observe_protocol_counter_scratch_data()
        + size_of::<Result<(), ProviderError>>();

    owner_loans
        + typed_loans
        + record_views
        + live_owner_views
        + prefix_and_admission_views
        + selected_contract_views
}

fn authenticate_suffix_selection_data<S: ProviderStream>(
    connection: &Connection<S>,
) -> Result<(), ProviderError> {
    let admission = connection.original_native_owned11_admission()?;
    admission.authenticate_current(connection)?;
    crate::reference_packet::service::native_startup::authenticate_restoration_suffix_selection_data(
        admission
            .policy
            .original_restoration_activation_selection_data(),
        &admission.authority,
    )
}

impl NativeRestorationObservationAttempt {
    // This is one necessary private entry predicate, never a witness issuer.
    fn authenticate_published_suffix_milestones_data(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if !self.received || !self.verified || !self.dispatched || !self.published {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_suffix_milestones_refuse_foreign_and_partial_attempts() {
        let original = crate::envelope::tests::request();
        let mut attempt = NativeRestorationObservationAttempt {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            original: None,
            body: None,
            artifact: None,
            context: None,
            terminal: None,
            received: false,
            verified: false,
            dispatched: false,
            published: false,
        };
        attempt.retain_original_data(original.clone()).unwrap();
        attempt.received = true;
        attempt.verified = true;
        attempt.dispatched = true;
        assert!(
            attempt
                .authenticate_published_suffix_milestones_data()
                .is_err()
        );
        assert_eq!(attempt.original.as_ref(), Some(&original));
        assert!(attempt.retain_original_data(original.clone()).is_err());

        // Passing this DATA predicate does not construct any boot, released
        // scope, signed artifact, terminal or positive private witness.
        attempt.published = true;
        attempt
            .authenticate_published_suffix_milestones_data()
            .unwrap();
        attempt.creator = std::process::id().checked_add(1).unwrap();
        assert!(
            attempt
                .authenticate_published_suffix_milestones_data()
                .is_err()
        );
        assert_eq!(attempt.original.as_ref(), Some(&original));
        assert!(attempt.artifact.is_none() && attempt.terminal.is_none());
    }
}
