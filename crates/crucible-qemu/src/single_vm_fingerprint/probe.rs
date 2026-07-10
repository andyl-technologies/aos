//! Instruction-exact probe contract for live single-VM divergence refinement.
//!
//! The coarse run-twice gate identifies a bounded icount window. A production
//! backend implements [`SingleVmFingerprintProbeRunner`] by restarting or
//! restoring each fixed run to requested aggregate icounts. This module owns
//! the fallible binary search and requires a complete both-side state dump at
//! the first differing instruction.

use super::{
    SINGLE_VM_FINGERPRINT_DIGEST_BYTES, SingleVmFingerprintBisectionError,
    SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionRequest,
    SingleVmFingerprintDivergenceStateDump, SingleVmFingerprintRunOrdinal,
    SingleVmFingerprintRunStateDump, SingleVmFingerprintScenario,
};

/// One exact-icount fingerprint returned by a live probe backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintProbe {
    ordinal: SingleVmFingerprintRunOrdinal,
    node: String,
    icount: u64,
    definition_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
    run_inputs_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
    prefix_fingerprint: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
}

impl SingleVmFingerprintProbe {
    /// Builds one exact probe observation.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintBisectionError`] when the node is empty.
    pub fn new(
        ordinal: SingleVmFingerprintRunOrdinal,
        node: impl Into<String>,
        icount: u64,
        definition_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
        run_inputs_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
        prefix_fingerprint: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
    ) -> Result<Self, SingleVmFingerprintBisectionError> {
        let node = node.into();
        if node.is_empty() {
            return Err(SingleVmFingerprintBisectionError::new(
                "probe node must be non-empty",
            ));
        }
        Ok(Self {
            ordinal,
            node,
            icount,
            definition_digest,
            run_inputs_digest,
            prefix_fingerprint,
        })
    }

    /// Returns which of the two fixed runs produced this probe.
    #[must_use]
    pub const fn ordinal(&self) -> SingleVmFingerprintRunOrdinal {
        self.ordinal
    }

    /// Returns the stable node observed by the probe.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the exact aggregate instruction count.
    #[must_use]
    pub const fn icount(&self) -> u64 {
        self.icount
    }

    /// Returns the canonical observation-definition digest used by this probe.
    #[must_use]
    pub const fn definition_digest(&self) -> &[u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES] {
        &self.definition_digest
    }

    /// Returns the content digest of the exact image/cmdline/seed/input tuple.
    #[must_use]
    pub const fn run_inputs_digest(&self) -> &[u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES] {
        &self.run_inputs_digest
    }

    /// Returns the cumulative canonical fingerprint through this icount.
    ///
    /// Once two cumulative prefix fingerprints differ they cannot reconverge:
    /// each later digest folds the previous digest into the next sample.
    #[must_use]
    pub const fn prefix_fingerprint(&self) -> &[u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES] {
        &self.prefix_fingerprint
    }
}

/// One fixed-run request to stop and observe an exact aggregate icount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintProbeRequest {
    scenario: SingleVmFingerprintScenario,
    ordinal: SingleVmFingerprintRunOrdinal,
    target_icount: u64,
}

impl SingleVmFingerprintProbeRequest {
    /// Builds a bounded exact-icount probe request.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintBisectionError`] when the target exceeds
    /// the scenario's configured run horizon. Target zero requests the paused
    /// pre-execution genesis fingerprint.
    pub fn new(
        scenario: SingleVmFingerprintScenario,
        ordinal: SingleVmFingerprintRunOrdinal,
        target_icount: u64,
    ) -> Result<Self, SingleVmFingerprintBisectionError> {
        if target_icount > scenario.run_horizon_icount {
            return Err(SingleVmFingerprintBisectionError::new(format!(
                "probe icount {target_icount} must be within 0..={}",
                scenario.run_horizon_icount
            )));
        }
        Ok(Self {
            scenario,
            ordinal,
            target_icount,
        })
    }

    /// Returns the exact fixed scenario to replay.
    #[must_use]
    pub const fn scenario(&self) -> &SingleVmFingerprintScenario {
        &self.scenario
    }

    /// Returns which comparison run must be replayed.
    #[must_use]
    pub const fn ordinal(&self) -> SingleVmFingerprintRunOrdinal {
        self.ordinal
    }

    /// Returns the exact aggregate instruction count to observe.
    #[must_use]
    pub const fn target_icount(&self) -> u64 {
        self.target_icount
    }
}

/// One provenance-bound full state dump returned by a live probe backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintStateDumpProbe {
    ordinal: SingleVmFingerprintRunOrdinal,
    definition_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
    run_inputs_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
    state: SingleVmFingerprintRunStateDump,
}

impl SingleVmFingerprintStateDumpProbe {
    /// Binds a full state dump to one exact run configuration and ordinal.
    #[must_use]
    pub const fn new(
        ordinal: SingleVmFingerprintRunOrdinal,
        definition_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
        run_inputs_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
        state: SingleVmFingerprintRunStateDump,
    ) -> Self {
        Self {
            ordinal,
            definition_digest,
            run_inputs_digest,
            state,
        }
    }

    /// Returns which fixed run produced the dump.
    #[must_use]
    pub const fn ordinal(&self) -> SingleVmFingerprintRunOrdinal {
        self.ordinal
    }

    /// Returns the observation-definition digest used by the dump run.
    #[must_use]
    pub const fn definition_digest(&self) -> &[u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES] {
        &self.definition_digest
    }

    /// Returns the exact run-input tuple digest used by the dump run.
    #[must_use]
    pub const fn run_inputs_digest(&self) -> &[u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES] {
        &self.run_inputs_digest
    }

    /// Returns the complete architectural dump.
    #[must_use]
    pub const fn state(&self) -> &SingleVmFingerprintRunStateDump {
        &self.state
    }

    fn into_state(self) -> SingleVmFingerprintRunStateDump {
        self.state
    }
}

/// A live backend capable of exact fingerprint probes and full state dumps.
pub trait SingleVmFingerprintProbeRunner {
    /// Restarts or restores one fixed run and observes the requested icount.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintBisectionError`] when the backend cannot
    /// reproduce the run at the exact requested instruction boundary.
    fn probe_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintProbe, SingleVmFingerprintBisectionError>;

    /// Emits complete architectural state for one run at the requested icount.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintBisectionError`] when the backend cannot
    /// reproduce the boundary or collect full registers, differing-memory
    /// candidates, current non-RAM VMState, and retained canonical events.
    fn dump_single_vm_fingerprint_state(
        &mut self,
        request: &SingleVmFingerprintProbeRequest,
    ) -> Result<SingleVmFingerprintStateDumpProbe, SingleVmFingerprintBisectionError>;
}

/// Refines a coarse stream mismatch to one exact instruction and state dump.
///
/// Every probe error is propagated. The search never interprets a failed or
/// malformed backend observation as either equality or divergence.
///
/// # Errors
///
/// Returns [`SingleVmFingerprintBisectionError`] when the coarse window is not
/// bisectable, an endpoint does not have its claimed equality state, any probe
/// is malformed or fails, or the final both-side state dump is invalid.
pub fn bisect_single_vm_fingerprint_with_probes<Runner>(
    runner: &mut Runner,
    request: &SingleVmFingerprintBisectionRequest,
) -> Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError>
where
    Runner: SingleVmFingerprintProbeRunner,
{
    let mismatch = request.mismatch();
    let mut low = mismatch.previous_matching_icount.unwrap_or(0);
    let mut high = mismatch.first_different_icount.ok_or_else(|| {
        SingleVmFingerprintBisectionError::new(
            "coarse mismatch does not identify a differing sample icount",
        )
    })?;
    if low >= high || high > request.scenario().run_horizon_icount {
        return Err(SingleVmFingerprintBisectionError::new(format!(
            "invalid coarse bisection window {low}..{high}"
        )));
    }
    let expected_node = mismatch_node(request)?;
    let mut low_pair = probe_pair(runner, request.scenario(), low, expected_node)?;
    if !low_pair.matches() {
        return Err(SingleVmFingerprintBisectionError::new(format!(
            "coarse low endpoint {low} already differs"
        )));
    }
    let mut high_pair = probe_pair(runner, request.scenario(), high, expected_node)?;
    if high_pair.matches() {
        return Err(SingleVmFingerprintBisectionError::new(format!(
            "coarse high endpoint {high} still matches"
        )));
    }

    while high - low > 1 {
        let midpoint = low + ((high - low) / 2);
        let midpoint_pair = probe_pair(runner, request.scenario(), midpoint, expected_node)?;
        if midpoint_pair.matches() {
            low = midpoint;
            low_pair = midpoint_pair;
        } else {
            high = midpoint;
            high_pair = midpoint_pair;
        }
    }

    if probe_pair(runner, request.scenario(), low, expected_node)? != low_pair
        || probe_pair(runner, request.scenario(), high, expected_node)? != high_pair
    {
        return Err(SingleVmFingerprintBisectionError::new(
            "final exact probe endpoints were not reproducible",
        ));
    }

    let first_request = SingleVmFingerprintProbeRequest::new(
        request.scenario().clone(),
        SingleVmFingerprintRunOrdinal::First,
        high,
    )?;
    let second_request = SingleVmFingerprintProbeRequest::new(
        request.scenario().clone(),
        SingleVmFingerprintRunOrdinal::Second,
        high,
    )?;
    let first_dump = runner.dump_single_vm_fingerprint_state(&first_request)?;
    let second_dump = runner.dump_single_vm_fingerprint_state(&second_request)?;
    validate_state_dump_probe(&first_dump, &first_request, expected_node)?;
    validate_state_dump_probe(&second_dump, &second_request, expected_node)?;
    let state_dump = SingleVmFingerprintDivergenceStateDump::new(
        first_dump.into_state(),
        second_dump.into_state(),
    )
    .map_err(|error| SingleVmFingerprintBisectionError::new(error.to_string()))?;

    SingleVmFingerprintBisectionReport::new(
        mismatch.sample_index,
        mismatch.previous_matching_icount,
        mismatch.first_different_icount.ok_or_else(|| {
            SingleVmFingerprintBisectionError::new(
                "coarse mismatch lost its differing sample icount",
            )
        })?,
        low,
        high,
        request.scenario(),
        state_dump,
    )
    .map_err(|error| SingleVmFingerprintBisectionError::new(error.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SingleVmFingerprintProbePair {
    first: SingleVmFingerprintProbe,
    second: SingleVmFingerprintProbe,
}

impl SingleVmFingerprintProbePair {
    fn matches(&self) -> bool {
        self.first.prefix_fingerprint() == self.second.prefix_fingerprint()
    }
}

fn probe_pair<Runner>(
    runner: &mut Runner,
    scenario: &SingleVmFingerprintScenario,
    icount: u64,
    expected_node: &str,
) -> Result<SingleVmFingerprintProbePair, SingleVmFingerprintBisectionError>
where
    Runner: SingleVmFingerprintProbeRunner,
{
    let first_request = SingleVmFingerprintProbeRequest::new(
        scenario.clone(),
        SingleVmFingerprintRunOrdinal::First,
        icount,
    )?;
    let second_request = SingleVmFingerprintProbeRequest::new(
        scenario.clone(),
        SingleVmFingerprintRunOrdinal::Second,
        icount,
    )?;
    let first = runner.probe_single_vm_fingerprint(&first_request)?;
    let second = runner.probe_single_vm_fingerprint(&second_request)?;
    validate_probe(&first, &first_request, expected_node)?;
    validate_probe(&second, &second_request, expected_node)?;
    Ok(SingleVmFingerprintProbePair { first, second })
}

fn validate_probe(
    probe: &SingleVmFingerprintProbe,
    request: &SingleVmFingerprintProbeRequest,
    expected_node: &str,
) -> Result<(), SingleVmFingerprintBisectionError> {
    if probe.ordinal() != request.ordinal()
        || probe.node() != expected_node
        || probe.icount() != request.target_icount()
        || probe.definition_digest() != request.scenario().fingerprint_definition_digest()
        || probe.run_inputs_digest() != &request.scenario().run_inputs().content_digest()
    {
        return Err(SingleVmFingerprintBisectionError::new(format!(
            "probe result does not match requested ordinal/node/icount/definition/inputs at {}",
            request.target_icount()
        )));
    }
    Ok(())
}

fn validate_state_dump_probe(
    dump: &SingleVmFingerprintStateDumpProbe,
    request: &SingleVmFingerprintProbeRequest,
    expected_node: &str,
) -> Result<(), SingleVmFingerprintBisectionError> {
    if dump.ordinal() != request.ordinal()
        || dump.definition_digest() != request.scenario().fingerprint_definition_digest()
        || dump.run_inputs_digest() != &request.scenario().run_inputs().content_digest()
        || dump.state().node() != expected_node
        || dump.state().icount() != request.target_icount()
        || dump.state().vcpu_registers().len() != request.scenario().expected_vcpu_count()
    {
        return Err(SingleVmFingerprintBisectionError::new(format!(
            "state dump does not match requested ordinal/node/icount/topology/definition/inputs at {}",
            request.target_icount()
        )));
    }
    Ok(())
}

fn mismatch_node(
    request: &SingleVmFingerprintBisectionRequest,
) -> Result<&str, SingleVmFingerprintBisectionError> {
    let index = request.mismatch().sample_index;
    let first = request
        .first_stream()
        .samples
        .get(index)
        .or_else(|| request.first_stream().samples.last());
    let second = request
        .second_stream()
        .samples
        .get(index)
        .or_else(|| request.second_stream().samples.last());
    match (first, second) {
        (Some(first), Some(second)) if first.node == second.node => Ok(&first.node),
        _ => Err(SingleVmFingerprintBisectionError::new(
            "coarse mismatch streams do not identify one responsible node",
        )),
    }
}
