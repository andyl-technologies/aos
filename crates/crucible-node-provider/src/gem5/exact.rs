//! Sealed closed-profile authority and checked superdense callback mediation.
//!
//! Native callbacks occupy reaction slots `2 * (tick_ordinal - 1)`, leaving the
//! following microstep for original publication custody. Idle native time and
//! the coordinator cursor remain distinct; a queue exclusion proof closes a
//! horizon without executing a callback at its exclusive coordinate.

use super::*;
use crate::gem5::Gem5CapturedImage;

/// Authenticates the installed clock, callback mapping, and finite closure cap.
pub trait Gem5ExactProfileVerifier: Gem5OpaqueProfileVerifier {
    /// Verifies one-picosecond native ticks and the installed callback mediation.
    ///
    /// The installed profile must exclude all asynchronous host and device
    /// ingress. Qualification must bind actual controller/model/native code,
    /// original stdout births, and the declared finite same-time budget.
    ///
    /// # Errors
    /// Refuses unsupported clocks, unqualified mediation, ingress, or a cap
    /// outside the installed scenario/profile qualification.
    fn verify_superdense_mapping(
        &self,
        launch: &Gem5Launch,
        maximum_microsteps: U64,
    ) -> Result<(), ProviderError>;
}

/// Seals exact execution to one independently audited, actual live native peer.
///
/// A source certificate cannot qualify a reconstructed incarnation. A fresh
/// owner requires its own authenticated unchanged-cut live closure before this
/// authority can be minted. The partial modeled diagnostics remain incomplete.
#[derive(Debug)]
pub struct Gem5ExactAuthority {
    pid: u32,
    start_ticks: String,
    source_scope: crucible_node_contract::HashRef,
    maximum_microsteps: U64,
    evidence: ContentRef,
    bytes: Vec<u8>,
}

impl Gem5ExactAuthority {
    /// Returns the installed finite same-time closure budget.
    pub fn maximum_microsteps(&self) -> U64 {
        self.maximum_microsteps
    }

    /// Returns the original immutable independent native closure evidence.
    pub fn evidence(&self) -> (&ContentRef, &[u8]) {
        (&self.evidence, &self.bytes)
    }

    fn verify_live(&self, process: &Gem5NativeProcess) -> Result<(), ProviderError> {
        self.evidence.verify(&self.bytes)?;
        if process.quarantine.is_some()
            || process.child_pid() != Some(self.pid)
            || closure::kernel_start_ticks(self.pid)? != self.start_ticks
            || closure::source_scope(&process.launch)? != self.source_scope
        {
            return Err(ProviderError::Correlation(
                "gem5 exact authority names another live incarnation",
            ));
        }
        Ok(())
    }
}

impl Gem5NativeProcess {
    /// Qualifies exact controls using independent image closure and installed policy.
    ///
    /// # Errors
    /// Refuses changed images, foreign or stale native closure, unqualified
    /// installed code/clock/input policy, unresolved custody, or a finite cap
    /// that cannot represent the actual stopped coordinator position.
    pub fn qualify_exact(
        &self,
        image: &Gem5CapturedImage,
        certificate: &Gem5ProcessClosure,
        auditor: &Gem5LaunchArtifact,
        verifier: &dyn Gem5ExactProfileVerifier,
        maximum_microsteps: U64,
    ) -> Result<Gem5ExactAuthority, ProviderError> {
        certificate.verify_image(image)?;
        if self.quarantine.is_some()
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
            || certificate.auditor() != &auditor.content
            || maximum_microsteps.get() < 2
            || self.boundary.logical_position.microstep >= maximum_microsteps
        {
            return Err(ProviderError::Correlation(
                "gem5 exact readiness lacks complete current custody",
            ));
        }
        verifier.verify_opaque_profile(&self.launch, auditor)?;
        verifier.verify_superdense_mapping(&self.launch, maximum_microsteps)?;
        let (pid, start_ticks, source_scope) = certificate.live_scope(self)?;
        let (evidence, bytes) = certificate.evidence();
        Ok(Gem5ExactAuthority {
            pid,
            start_ticks,
            source_scope,
            maximum_microsteps,
            evidence: evidence.clone(),
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the authentic retained coordinator cursor without running events.
    pub fn logical_position(&self) -> Position {
        self.boundary.logical_position
    }

    /// Returns the next possible publication under the sealed no-ingress profile.
    ///
    /// This bound includes retained native births awaiting coordinator custody.
    /// A queue with no next callback returns no finite bound; callers must retain
    /// the explicit closed-profile idle proof instead of inventing infinity.
    ///
    /// # Errors
    /// Refuses foreign live authority or exhausted same-time coordinates.
    pub fn next_publication_bound(
        &self,
        authority: &Gem5ExactAuthority,
    ) -> Result<Option<Position>, ProviderError> {
        authority.verify_live(self)?;
        if let Some(publication) = self
            .pending_completion()
            .and_then(|prefix| prefix.publications.first())
        {
            return Ok(Some(publication_position(
                publication,
                authority.maximum_microsteps,
            )?));
        }
        self.boundary
            .next_reaction(authority.maximum_microsteps)?
            .map(|reaction| {
                reaction
                    .reaction_publication(authority.maximum_microsteps)
                    .map_err(ProviderError::from)
            })
            .transpose()
    }

    /// Executes one original exact prefix under the sealed live profile authority.
    ///
    /// Budget completion is progress of the original enclosing operation. The
    /// caller retains that operation and immutable prefix evidence before any
    /// administrative ACK; publication output requires coordinator custody ACK.
    ///
    /// # Errors
    /// Refuses foreign authority, absent or changed exact scope, invalid finite
    /// ceilings, held original custody, transport uncertainty, or native overshoot.
    pub fn run_exact(
        &mut self,
        authority: &Gem5ExactAuthority,
        original: Gem5Run,
    ) -> Result<Gem5Completion, ProviderError> {
        authority.verify_live(self)?;
        if original
            .exact_range
            .as_ref()
            .is_none_or(|range| range.maximum_microsteps != authority.maximum_microsteps)
        {
            return Err(ProviderError::Correlation(
                "gem5 exact prefix differs from installed closure policy",
            ));
        }
        self.run_internal(original)
    }
}

pub(super) fn same_native_state(left: &Gem5Boundary, right: &Gem5Boundary) -> bool {
    let mut normalized = right.clone();
    normalized.logical_position = left.logical_position;
    left == &normalized
}

pub(super) fn validate_exact_request(
    boundary: &Gem5Boundary,
    run: &Gem5Run,
) -> Result<(), ProviderError> {
    let Some(range) = &run.exact_range else {
        return Ok(());
    };
    if range.start != boundary.logical_position
        || range.start >= range.limit
        || range.maximum_microsteps.get() < 2
        || range.start.microstep >= range.maximum_microsteps
        || range.limit.microstep >= range.maximum_microsteps
        || run.exclusive_tick != range.limit.time_ps
    {
        return Err(ProviderError::Correlation(
            "gem5 exact request differs from stopped full coordinate",
        ));
    }
    Ok(())
}

pub(super) fn validate_exact_completion(receipt: &Gem5Completion) -> Result<(), ProviderError> {
    let Some(range) = &receipt.original.exact_range else {
        return Ok(());
    };
    validate_exact_request(&receipt.before, &receipt.original)?;
    let reached = receipt.after.logical_position;
    if reached < range.start
        || reached > range.limit
        || reached.microstep >= range.maximum_microsteps
    {
        return Err(ProviderError::Correlation(
            "gem5 exact native prefix outruns its full coordinate",
        ));
    }
    if receipt.processed_events.get() > 0 {
        let reaction = callback_position(
            receipt.after.tick,
            receipt.after.tick_ordinal,
            range.maximum_microsteps,
        )?;
        if reaction < range.start || reaction >= range.limit || reaction >= reached {
            return Err(ProviderError::Correlation(
                "gem5 callback is outside its original exact interval",
            ));
        }
    }
    if matches!(receipt.reason.as_str(), "horizon" | "idle") {
        if reached != range.limit
            || receipt
                .after
                .next_reaction(range.maximum_microsteps)?
                .is_some_and(|next| next < range.limit)
        {
            return Err(ProviderError::Correlation(
                "gem5 horizon lacks native callback exclusion",
            ));
        }
    } else if receipt.processed_events.get() == 0 || reached.phase != Phase::BoundaryControl {
        return Err(ProviderError::Correlation(
            "gem5 progress lacks actual native reaction custody",
        ));
    }
    for publication in &receipt.publications {
        let reaction = callback_position(
            publication.tick,
            publication.tick_ordinal,
            range.maximum_microsteps,
        )?;
        if reaction < range.start || reaction >= range.limit {
            return Err(ProviderError::Correlation(
                "gem5 publication birth is outside its original exact interval",
            ));
        }
        publication_position(publication, range.maximum_microsteps)?;
    }
    Ok(())
}

fn callback_position(tick: U64, tie: U64, cap: U64) -> Result<Position, ProviderError> {
    let microstep = tie
        .get()
        .checked_sub(1)
        .and_then(|value| value.checked_mul(2))
        .ok_or(ProviderError::ResourceExhausted("gem5 callback ordinal"))?;
    if microstep
        .checked_add(1)
        .is_none_or(|publication| publication >= cap.get())
    {
        return Err(ProviderError::ResourceExhausted(
            "gem5 finite same-time closure",
        ));
    }
    Ok(Position::new(tick, U64::new(microstep), Phase::Reaction))
}

fn publication_position(
    publication: &crate::gem5::Gem5ConsolePublication,
    cap: U64,
) -> Result<Position, ProviderError> {
    callback_position(publication.tick, publication.tick_ordinal, cap)?
        .reaction_publication(cap)
        .map_err(ProviderError::from)
}
