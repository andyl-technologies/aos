//! Native gem5 effects under the common authenticated CNP request journal.
//!
//! A private native prefix is progress within an original public operation, not
//! a public terminal outcome. Installed adapters must authenticate complete
//! CNP evidence before the common journal records completion or releases custody.

use crucible_node_contract::{Id, U64, Validate};

use crate::{
    ProviderError,
    bodies::{BeginArguments, BeginRequest},
    envelope::{Envelope, Method},
    handshake::ConnectionAuthority,
    native_journal::{
        BeginRegistration, NativeContinuationVerifier, NativeJournal, NativeOperationPermit,
        NativeRequestPermit, NativeScopeVerifier, OperationSnapshot,
    },
};

use super::{
    Gem5Boundary, Gem5Completion, Gem5CustodySlot, Gem5Launch, Gem5NativeProcess, Gem5Run,
};

/// Retains inert installation facts and the actual native owner under CNP custody.
pub struct Gem5OwnerResources {
    launch: Gem5Launch,
    supervision: Option<Box<dyn Gem5CustodySlot>>,
    process: Option<Gem5NativeProcess>,
}

impl Gem5OwnerResources {
    /// Creates inert native resources before the common journal reserves supervision.
    ///
    /// No native process is launched here. Installed launch qualification and
    /// CNP realization authorization remain mandatory at the original request.
    pub fn new(launch: Gem5Launch, supervision: Box<dyn Gem5CustodySlot>) -> Self {
        Self {
            launch,
            supervision: Some(supervision),
            process: None,
        }
    }

    /// Returns immutable source/model/resource installation facts.
    pub fn launch(&self) -> &Gem5Launch {
        &self.launch
    }

    /// Returns genuine native readiness after original realization succeeds.
    pub fn boundary(&self) -> Option<&Gem5Boundary> {
        self.process.as_ref().map(Gem5NativeProcess::boundary)
    }

    /// Authenticates a completed private prefix against actual native custody.
    ///
    /// # Errors
    /// Rejects absent native realization or foreign/changed caller-created receipts.
    pub fn validate_native_completion(
        &self,
        receipt: &Gem5Completion,
    ) -> Result<(), ProviderError> {
        self.process
            .as_ref()
            .ok_or(ProviderError::Correlation("gem5 native realization absent"))?
            .validate_completion(receipt)
    }
}

/// Authenticates the complete installed realization before actual native launch.
pub trait Gem5RealizationVerifier {
    /// Verifies original configuration, selected models, references and resource ceilings.
    ///
    /// # Errors
    /// Rejects unpinned or changed configuration, unsupported devices, missing
    /// qualification, invalid requested participant coverage or unavailable resources.
    fn verify_realization(
        &self,
        resources: &Gem5OwnerResources,
        original: &Envelope,
    ) -> Result<(), ProviderError>;
}

/// Launches actual native resources only beneath their original CNP realization request.
///
/// The original opaque permit remains bound to the same journal request. A retry
/// has no replacement permit and cannot spawn a second native owner.
///
/// # Errors
/// Rejects foreign permits, another method, unavailable installation authority,
/// already realized resources or native launch failure. Started uncertainty remains
/// in the common journal and actual process handles remain supervised.
pub fn realize_gem5(
    journal: &mut NativeJournal<Gem5OwnerResources>,
    permit: &NativeRequestPermit,
    verifier: &dyn Gem5RealizationVerifier,
) -> Result<Gem5Boundary, ProviderError> {
    let key = permit.request_key();
    let original = journal.request_material(key.origin, &key.id)?;
    if original.method != Method::Realize {
        return Err(ProviderError::Correlation(
            "gem5 native launch is not original realization",
        ));
    }
    verifier.verify_realization(journal.resources(), original)?;
    journal.with_request_resources(permit, |resources| {
        if resources.process.is_some() {
            return Err(ProviderError::Conflict(
                "gem5 native owner already realized",
            ));
        }
        let slot = resources
            .supervision
            .take()
            .ok_or(ProviderError::Correlation(
                "gem5 preallocated native supervision absent",
            ))?;
        let process = Gem5NativeProcess::spawn(resources.launch.clone(), slot)?;
        let boundary = process.boundary().clone();
        resources.process = Some(process);
        Ok(boundary)
    })
}

/// Admits an original exact CNP operation only after complete native state qualification.
///
/// The installed scope verifier must authenticate actual world activation,
/// complete inputs, selected facet, owner binding and all participant domains.
/// Private event control alone never supplies that authority.
///
/// # Errors
/// Rejects incomplete native observers, unsupported public operations, absent
/// resources or any original grant/binding/activation validation failure.
pub fn register_gem5_exact(
    journal: &mut NativeJournal<Gem5OwnerResources>,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    original: &BeginRequest,
    verifier: &dyn NativeScopeVerifier<Gem5OwnerResources>,
) -> Result<BeginRegistration, ProviderError> {
    original.validate()?;
    if !matches!(original.decoded_arguments()?, BeginArguments::ExactRun(_)) {
        return Err(ProviderError::Correlation(
            "gem5 installed exact adapter does not qualify this operation",
        ));
    }
    journal
        .resources()
        .process
        .as_ref()
        .ok_or(ProviderError::Correlation(
            "gem5 actual native owner absent",
        ))?
        .require_complete_inventory()?;
    journal.register_begin(authority, envelope, original, verifier)
}

/// Services one bounded private native prefix of an original admitted exact operation.
///
/// Event-budget exhaustion remains native progress within the same public grant.
/// This function records no public terminal response, output publication, or ACK.
/// A later continuation requires an independently authenticated original poll;
/// it cannot reuse this one-shot begin permit.
///
/// # Errors
/// Rejects incomplete observers, mismatched original owner/grant, invalid native
/// event ceilings, exhausted prefix credit or uncertain native transport/effects.
pub fn run_gem5_prefix(
    journal: &mut NativeJournal<Gem5OwnerResources>,
    permit: &NativeOperationPermit,
    maximum_events: U64,
) -> Result<Gem5Completion, ProviderError> {
    let original = journal
        .snapshot()
        .operations
        .get(permit.operation_id())
        .ok_or(ProviderError::Correlation(
            "gem5 original CNP operation absent",
        ))?;
    let run = prefix_request(journal.resources(), original, maximum_events)?;
    journal.with_operation_resources(permit, |resources| {
        resources
            .process
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "gem5 admitted native owner omitted",
            ))?
            .run(run)
    })
}

/// Continues a running original exact grant beneath a distinct authenticated poll.
///
/// An installed native verifier must prove unchanged original grant/input scope
/// and authentic prior prefix custody. An event-budget receipt with no output
/// is retained before its private administrative acknowledgment. Actual output
/// remains held for coordinator publication; this path never acknowledges it.
///
/// # Errors
/// Rejects reused poll permits, unknown or completed operations, unavailable
/// native qualification, foreign prefix receipts, held output and native errors.
pub fn continue_gem5_prefix(
    journal: &mut NativeJournal<Gem5OwnerResources>,
    authority: &ConnectionAuthority,
    poll: &NativeRequestPermit,
    verifier: &dyn NativeContinuationVerifier<Gem5OwnerResources>,
    maximum_events: U64,
) -> Result<Gem5Completion, ProviderError> {
    let envelope = journal.request_material(poll.request_key().origin, &poll.request_key().id)?;
    let operation = envelope
        .operation_id
        .0
        .as_ref()
        .ok_or(ProviderError::Correlation(
            "gem5 continuation poll lacks original operation",
        ))?;
    let original =
        journal
            .snapshot()
            .operations
            .get(operation)
            .ok_or(ProviderError::Correlation(
                "gem5 continuation original operation absent",
            ))?;
    let run = prefix_request(journal.resources(), original, maximum_events)?;
    let held = journal
        .resources()
        .process
        .as_ref()
        .ok_or(ProviderError::Correlation("gem5 native owner absent"))?
        .pending_completion()
        .cloned();
    if let Some(receipt) = &held
        && (receipt.reason != "event_budget"
            || !receipt.output.is_empty()
            || !receipt.publications.is_empty())
    {
        return Err(ProviderError::Conflict(
            "gem5 original publication or terminal prefix remains held",
        ));
    }
    journal.with_running_operation_resources(authority, poll, verifier, |resources| {
        let process = resources
            .process
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "gem5 continuation native owner omitted",
            ))?;
        if let Some(receipt) = held {
            process.validate_completion(&receipt)?;
            process.acknowledge(&receipt.operation)?;
        }
        process.run(run)
    })
}

fn prefix_request(
    resources: &Gem5OwnerResources,
    original: &OperationSnapshot,
    maximum_events: U64,
) -> Result<Gem5Run, ProviderError> {
    if maximum_events.get() == 0 || maximum_events.get() > 10_000_000 {
        return Err(ProviderError::ResourceExhausted(
            "gem5 native prefix event allowance",
        ));
    }
    let BeginArguments::ExactRun(arguments) = original.original.decoded_arguments()? else {
        return Err(ProviderError::Correlation(
            "gem5 original operation is not exact execution",
        ));
    };
    let process = resources
        .process
        .as_ref()
        .ok_or(ProviderError::Correlation(
            "gem5 actual native owner absent",
        ))?;
    process.require_complete_inventory()?;
    if original.scope.execution_owner != process.launch().owner
        || original.scope.owner_generation != process.launch().generation
        || (process.boundary().has_next_event
            && process.boundary().next_tick < arguments.start.time_ps)
    {
        return Err(ProviderError::Correlation(
            "gem5 native owner or queued frontier violates original admitted grant",
        ));
    }
    let identity = crucible_node_contract::canonical::json_hash(
        "cnp.gem5-native-prefix.v1",
        &(
            &original.operation_id,
            &original.request_hash,
            process.boundary().ordinal,
        ),
    )?;
    Ok(Gem5Run {
        kind: "run".to_owned(),
        operation: Id::new(format!("prefix/{}", identity.digest))?,
        exclusive_tick: arguments.limit.time_ps,
        maximum_events,
        exact_range: None,
    })
}
