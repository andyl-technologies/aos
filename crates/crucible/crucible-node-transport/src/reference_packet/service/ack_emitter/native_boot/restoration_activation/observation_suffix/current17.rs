//! Lends actual completed native owners while a distinct17 action is prepared.
//!
//! The first seed comes only from the same Boot's privately completed first
//! observation under Initial15 ancestry. Later seeds are actual published
//! Observe17 children in the same nonrenewing bank. Every other initialized
//! progress family refuses until its defining publication bridge is connected.
//! No decoded scope, historical reader or matching model reference creates this
//! loan. The caller still authenticates the new Source signature and separately
//! funds the stopped-model comparison and producer before effects.

use super::*;
use crate::reference_packet::control::ReleasedWorldControlInputsData;
use crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationScope;
use crate::reference_packet::service::native_startup::NativeRestoredSettledActionAttempt;

type ActionOwner = Rc<RefCell<NativeRestoredSettledActionAttempt>>;
type PriorOwner = Option<(usize, ActionOwner)>;

/// Borrows the actual completed original, terminal and publication occurrence.
///
/// The enclosing private attempt stays immutably borrowed for the complete
/// callback. No reference to Control caches or the whole Boot crosses it.
pub(crate) struct NativeObservation17OwningCheckpointData<'a> {
    original: &'a Envelope,
    terminal: &'a Envelope,
    publication_record: usize,
    first_original: &'a Envelope,
    first_terminal: &'a Envelope,
    scope: &'a PacketRestorationActivationScope,
}

impl<'a> NativeObservation17OwningCheckpointData<'a> {
    /// Borrows the actual completed request owner.
    pub(crate) fn original_data(&self) -> &'a Envelope {
        self.original
    }

    /// Borrows its actual retained completed terminal.
    pub(crate) fn terminal_data(&self) -> &'a Envelope {
        self.terminal
    }

    /// Borrows the current generation's genuine first observation original.
    pub(crate) fn first_original_data(&self) -> &'a Envelope {
        self.first_original
    }

    /// Borrows that first owner's actual completed terminal.
    pub(crate) fn first_terminal_data(&self) -> &'a Envelope {
        self.first_terminal
    }

    /// Borrows the exact first/World scope from the same private completed owner.
    pub(crate) fn scope_data(&self) -> &'a PacketRestorationActivationScope {
        self.scope
    }

    /// Returns the same private completed publication occurrence.
    pub(crate) fn publication_record_data(&self) -> usize {
        self.publication_record
    }
}

impl NativeAckBoot {
    /// Checks genuine first/World ancestry before another receiving slot exists.
    ///
    /// This reborrows actual completed custody, not a current-model, receive,
    /// Source signature or row grant. Native receive and later funded current
    /// comparison retain their separate same-Boot/index/ledger boundaries.
    ///
    /// # Errors
    /// Refuses absent/foreign/partial first ancestry, changed World/Control or
    /// unsupported inherited/progress families and literal/ACK correspondence.
    pub(crate) fn authenticate_original_observation17_ancestry_data<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        let first = retained_first(boot)?;
        authenticate_first(boot, &first, connection, control, records)?;
        Ok(())
    }

    /// Lends genuine first ancestry without claiming that its model is current.
    ///
    /// Grant-free Capture uploads bind their complete Source request to this
    /// immutable World/first occurrence. Later Capture production independently
    /// selects and compares the newest actual modeled checkpoint.
    ///
    /// # Errors
    /// Refuses missing/foreign/partial first custody or changed actual World,
    /// Control, publication record or literal/ACK correspondence. The complete
    /// post-fence also runs when the caller's correspondence check refuses.
    pub(crate) fn with_original_capture17_ancestry_data<S: ProviderStream, R>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
        inspect: impl for<'a> FnOnce(
            &'a PacketRestorationActivationScope,
            &'a Envelope,
            &'a Envelope,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        let first = retained_first(boot)?;
        let index = authenticate_first(boot, &first, connection, control, records)?;
        let flight = first.try_borrow().map_err(|_| borrowed())?;
        flight.authenticate_published_suffix_milestones_data()?;
        let original = flight.original.as_ref().ok_or_else(refused)?;
        let terminal = flight.terminal.as_ref().ok_or_else(refused)?;
        let scope = &flight.artifact.as_ref().ok_or_else(refused)?.request.scope;
        let result = inspect(scope, original, terminal);
        drop(flight);
        if authenticate_first(boot, &first, connection, control, records)? != index {
            return Err(refused());
        }
        result
    }

    /// Lends the latest actual completed owner beside the same receiving slot.
    ///
    /// The callback encompasses quote, independent debit, funded stopped-model
    /// comparison and producer work. It receives no action or allocation grant
    /// from this lender. Boot and Control cache loans end before the callback;
    /// only the first ancestry and selected completed attempts remain borrowed.
    ///
    /// # Errors
    /// Refuses foreign actors/Boots, active or failed prior owners, unsupported
    /// ancestry/progress families, changed records/literals/ACKs or cached proof
    /// custody. Both post-fences run even when the callback refuses.
    pub(crate) fn with_original_observation17_checkpoint_data<S: ProviderStream, R>(
        boot: &Rc<RefCell<Self>>,
        receiving_index: usize,
        receiving: &ActionOwner,
        connection: &Connection<S>,
        control: &mut PacketControl,
        records: &[ExchangeRecord],
        inspect: impl for<'a> FnOnce(
            NativeObservation17OwningCheckpointData<'a>,
            &mut PacketControl,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        let first = retained_first(boot)?;
        let first_record = authenticate_first(boot, &first, connection, control, records)?;
        let prior = prior_owner(boot, receiving_index, receiving, first_record)?;
        // Keep ancestry borrowed even when the newest checkpoint is a later
        // action. The callback must compare the entire new signed scope and
        // actual first-proof reference against these genuine retained owners.
        let first_flight = first.try_borrow().map_err(|_| borrowed())?;
        first_flight.authenticate_published_suffix_milestones_data()?;
        let first_original = first_flight.original.as_ref().ok_or_else(refused)?;
        let first_terminal = first_flight.terminal.as_ref().ok_or_else(refused)?;
        let scope = &first_flight
            .artifact
            .as_ref()
            .ok_or_else(refused)?
            .request
            .scope;
        let result = if let Some((_, prior_attempt)) = &prior {
            let actual = prior_attempt.try_borrow().map_err(|_| borrowed())?;
            actual.with_published_observation_checkpoint17_data(|original, terminal, record| {
                authenticate_checkpoint(connection, control, records, original, terminal, record)?;
                let result = inspect(
                    NativeObservation17OwningCheckpointData {
                        original,
                        terminal,
                        publication_record: record,
                        first_original,
                        first_terminal,
                        scope,
                    },
                    control,
                );
                authenticate_checkpoint(connection, control, records, original, terminal, record)?;
                Ok(result)
            })?
        } else {
            let original = first_original;
            let terminal = first_terminal;
            authenticate_checkpoint(
                connection,
                control,
                records,
                original,
                terminal,
                first_record,
            )?;
            let result = inspect(
                NativeObservation17OwningCheckpointData {
                    original,
                    terminal,
                    publication_record: first_record,
                    first_original,
                    first_terminal,
                    scope,
                },
                control,
            );
            authenticate_checkpoint(
                connection,
                control,
                records,
                original,
                terminal,
                first_record,
            )?;
            result
        };
        let checked_first = authenticate_first(boot, &first, connection, control, records)?;
        let checked_prior = prior_owner(boot, receiving_index, receiving, checked_first)?;
        if checked_first != first_record || !same_prior(&prior, &checked_prior) {
            return Err(refused());
        }
        result
    }
}

fn retained_first(
    boot: &Rc<RefCell<NativeAckBoot>>,
) -> Result<Rc<RefCell<NativeRestorationObservationAttempt>>, ProviderError> {
    let owner = boot.try_borrow().map_err(|_| borrowed())?;
    owner.ensure_origin()?;
    Ok(Rc::clone(
        owner.restoration_observation.as_ref().ok_or_else(refused)?,
    ))
}

fn prior_owner(
    boot: &Rc<RefCell<NativeAckBoot>>,
    receiving_index: usize,
    receiving: &ActionOwner,
    first_record: usize,
) -> Result<PriorOwner, ProviderError> {
    let owner = boot.try_borrow().map_err(|_| borrowed())?;
    owner.ensure_origin()?;
    owner
        .restored_settled
        .as_ref()
        .ok_or_else(refused)?
        .original_observation17_prior_data(boot, receiving_index, receiving, first_record)
}

fn same_prior(left: &PriorOwner, right: &PriorOwner) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some((left_index, left_owner)), Some((right_index, right_owner))) => {
            left_index == right_index && Rc::ptr_eq(left_owner, right_owner)
        }
        _ => false,
    }
}

fn authenticate_checkpoint<S: ProviderStream>(
    connection: &Connection<S>,
    control: &PacketControl,
    records: &[ExchangeRecord],
    original: &Envelope,
    terminal: &Envelope,
    record: usize,
) -> Result<(), ProviderError> {
    let mut occurrence = None;
    for (index, exchange) in records.iter().enumerate() {
        if exchange.originals().contains(terminal) && occurrence.replace(index).is_some() {
            return Err(refused());
        }
    }
    if occurrence != Some(record) {
        return Err(refused());
    }
    records
        .get(record)
        .ok_or_else(refused)?
        .authenticate_observation17_publication_data(connection, original, terminal)?;
    control.authenticate_observation17_checkpoint_cache_data(original, terminal)
}

fn authenticate_first<S: ProviderStream>(
    boot: &Rc<RefCell<NativeAckBoot>>,
    first: &Rc<RefCell<NativeRestorationObservationAttempt>>,
    connection: &Connection<S>,
    control: &PacketControl,
    records: &[ExchangeRecord],
) -> Result<usize, ProviderError> {
    let admission = connection.original_native_owned11_admission()?;
    admission.authenticate_current(connection)?;
    if !Rc::ptr_eq(boot, &admission.boot) {
        return Err(refused());
    }

    let owner = boot.try_borrow().map_err(|_| borrowed())?;
    owner.authenticate_original_invocation_prepare_target_data()?;
    if owner
        .restoration_observation
        .as_ref()
        .is_none_or(|actual| !Rc::ptr_eq(actual, first))
        || owner
            .policy
            .as_ref()
            .is_none_or(|actual| !Rc::ptr_eq(actual, &admission.policy))
    {
        return Err(refused());
    }
    let first_record = owner
        .startup
        .as_ref()
        .and_then(|s| s.restored_suffix.as_ref())
        .ok_or_else(refused)?
        .original_observation17_seed_record_data(first)?;
    let observed = first.try_borrow().map_err(|_| borrowed())?;
    observed.authenticate_published_suffix_milestones_data()?;
    let request = &observed.artifact.as_ref().ok_or_else(refused)?.request;
    if observed.body.is_none() || observed.context.as_ref().ok_or_else(refused)?.request != *request
    {
        return Err(refused());
    }

    let world = owner.restoration_activation[1]
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
    let arm = owner.restoration_activation[0]
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
    let commit = owner
        .restoration
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
    world.ensure_origin()?;
    arm.ensure_origin()?;
    commit.ensure_origin()?;
    if !world.verified
        || !world.dispatched
        || !world.published
        || world.phase != PacketRestorationActivationPhase::WorldActivate
        || !arm.verified
        || !arm.dispatched
        || !arm.published
        || arm.phase != PacketRestorationActivationPhase::Arm
        || !commit.verified
        || !commit.installation_started
        || !commit.receipt_started
        || commit.completed_response.is_none()
        || commit.response_body.is_empty()
        || commit.receipt_body.is_empty()
        || commit
            .request
            .as_ref()
            .ok_or_else(refused)?
            .prepare
            .restoration
            .backend_schema
            .id
            .as_str()
            != "source-owned.packet-native-continuation/14"
        || world.artifact.as_ref().ok_or_else(refused)?.request.scope != request.scope
        || arm.artifact.as_ref().ok_or_else(refused)?.request.scope != request.scope
        || world.context.as_ref().ok_or_else(refused)?.request
            != world.artifact.as_ref().ok_or_else(refused)?.request
    {
        return Err(refused());
    }
    let hold = commit.physical_hold.as_ref().ok_or_else(refused)?;
    if hold.physical_gate_data()? {
        return Err(refused());
    }
    connection.authenticate_installed_complete_restoration(&commit.mapping)?;
    let world_original = world.original.as_ref().ok_or_else(refused)?;
    let world_terminal = world.terminal.as_ref().ok_or_else(refused)?;
    // World publication is private, monotonic and completed before first Observe.
    // Recheck its exact sent occurrence without regenerating receipt DTOs.
    let mut world_record = None;
    for (index, record) in records.iter().enumerate() {
        if record.originals().contains(world_terminal) {
            if world_record.replace(index).is_some()
                || index >= first_record
                || record.sent() != record.originals().len()
            {
                return Err(refused());
            }
            world_original.matches_response(world_terminal)?;
            for index in 0..record.originals().len() {
                record.original_sent_frame(connection, index)?;
            }
        }
    }
    if world_record.is_none() {
        return Err(refused());
    }
    let incoming = connection.original_restoration_incoming_literal_data(
        world_original,
        world.incoming_slot.ok_or_else(refused)?,
    )?;
    drop(incoming);
    control.authenticate_observation17_world_cache_data(ReleasedWorldControlInputsData {
        original: world_original,
        terminal: world_terminal,
        scope: &request.scope,
        boot,
        mapping: &commit.mapping,
        hold,
        policy: &admission.policy,
    })?;
    authenticate_checkpoint(
        connection,
        control,
        records,
        observed.original.as_ref().ok_or_else(refused)?,
        observed.terminal.as_ref().ok_or_else(refused)?,
        first_record,
    )?;
    Ok(first_record)
}

/// Counts the lender's fixed views; callback and producer rows remain separate.
pub(crate) fn original_observation17_checkpoint_owner_counter_scratch_data() -> usize {
    use std::mem::size_of;
    crate::reference_packet::control::original_released_world_inputs_counter_scratch_data()
        + size_of::<NativeObservation17OwningCheckpointData<'static>>()
        + size_of::<ActionOwner>() * 3 + size_of::<PriorOwner>() * 2
        + size_of::<std::cell::Ref<'static, NativeAckBoot>>()
        + size_of::<std::cell::Ref<'static, NativeRestorationObservationAttempt>>()
        + size_of::<std::cell::Ref<'static, NativeRestorationActivationAttempt>>() * 2
        + size_of::<std::cell::Ref<'static, NativeCompleteRestoreAttempt>>()
        + size_of::<std::cell::Ref<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, ExchangeRecord>>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, ActionOwner>>>()
        + size_of::<Option<usize>>() * 3 + size_of::<Result<(), ProviderError>>() * 6
        + size_of::<&Envelope>() * 6 + size_of::<&ExchangeRecord>()
        + size_of::<[u8;32]>() * 2 + size_of::<blake3::Hasher>()
        + crate::reference_packet::service::native_startup::original_native_observation17_retained_counter_scratch_data()
        + crate::connection::original_observation17_publication_counter_scratch_data()
        + crate::connection::original_restoration_release_literal_counter_scratch_data()
        + crate::reference_packet::service::native_startup::original_native_invocation_counter_scratch_data()
}
