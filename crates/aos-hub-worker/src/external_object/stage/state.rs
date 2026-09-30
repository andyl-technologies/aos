//! Physical multipart ownership, immutable closure and narrowly retryable reads.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{
    DirectManifestCommitment, DirectManifestPart, DirectPart, WireInteger,
};
use aos_hub_core::storage_authority::{
    external_object::stage::{
        ExternalStageAdmissionMode, ExternalStageContext, ExternalStageOperation as Operation,
        ExternalStageOutcome as Outcome,
    },
    lease::{LeaseClock, LeaseEffect, LeaseInteger},
    GuardIncarnation,
};
use serde::{Deserialize, Serialize};

use super::super::{
    config::Config as ObjectConfig,
    protocol::{digest, digest_string},
    state::{Head, VisibleKind, VisibleReceipt, MAX_RECEIPTS},
};
use super::{
    config::Config,
    protocol::{Intent, Receipt, SourceProof, Turn},
};

pub(in crate::external_object) const MAX_INCARNATION: u64 = 9_007_199_254_740_991;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Creating,
    Active,
    Freezing,
    Frozen,
    Closed,
    Verified,
    DestinationActive,
    Aborted,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReceiptRef {
    pub operation_id: String,
    pub digest: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct Session {
    pub context: ExternalStageContext,
    pub configuration: String,
    pub destination: bool,
    pub phase: Phase,
    pub upload_id: Option<String>,
    pub manifest: Option<DirectManifestCommitment>,
    pub frozen_parts: u32,
    pub grant_horizon: WireInteger,
    pub grant_count: u32,
    pub upload_id_visibility_closed: bool,
    pub pending: Option<Turn>,
    pub pending_parts: Vec<PartTurnRef>,
    pub closed: Option<ReceiptRef>,
    pub verified: Option<ReceiptRef>,
    pub source: Option<SourceProof>,
}

/// Compact head reference; the exact complete turn lives in its own KV record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::external_object) struct PartTurnRef {
    pub part_number: u32,
    pub operation_id: String,
    pub intent_digest: String,
    pub dispatch_nonce: String,
    pub expected_incarnation: WireInteger,
}

impl PartTurnRef {
    pub(super) fn from_turn(turn: &Turn) -> Result<Self> {
        let Operation::CopyDestinationPart { part, .. } = &turn.intent.operation else {
            anyhow::bail!("part reference requires exact copy operation");
        };
        turn.intent.validate()?;
        ensure!(
            digest_string(&turn.dispatch_nonce),
            "part dispatch nonce invalid"
        );
        Ok(Self {
            part_number: part.part_number,
            operation_id: turn.intent.operation_id.clone(),
            intent_digest: turn.intent.fingerprint()?,
            dispatch_nonce: turn.dispatch_nonce.clone(),
            expected_incarnation: turn.expected_incarnation,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PartRecord {
    pub part: DirectPart,
    pub highest_grant_revision: WireInteger,
    pub grant_horizon: WireInteger,
    pub frozen: Option<DirectManifestPart>,
}

impl Session {
    /// Refuses cleanup observations while a physical session is active or unknown.
    pub(in crate::external_object) fn cleanup_ready(&self) -> bool {
        self.pending.is_none()
            && self.pending_parts.is_empty()
            && matches!(self.phase, Phase::Closed | Phase::Aborted)
    }

    pub(super) fn initialize(
        config: &Config,
        intent: &Intent,
        source: Option<SourceProof>,
    ) -> Result<Self> {
        ensure!(
            matches!(
                intent.operation,
                Operation::CreateStage | Operation::CreateDestination { .. }
            ),
            "session absent for follow-up control"
        );
        let destination = intent.operation.destination();
        if let Operation::CreateDestination {
            verified_stage_receipt_digest,
        } = &intent.operation
        {
            let proof = source
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("destination requires verified immutable stage"))?;
            proof.validate(&intent.context, verified_stage_receipt_digest)?;
            ensure!(
                proof.configuration == digest(config)?,
                "source configuration differs"
            );
        } else {
            ensure!(source.is_none(), "stage Create has unexpected source proof");
        }
        Ok(Self {
            context: intent.context.clone(),
            configuration: digest(config)?,
            destination,
            phase: Phase::Creating,
            upload_id: None,
            manifest: None,
            frozen_parts: 0,
            grant_horizon: WireInteger::new(0),
            grant_count: 0,
            upload_id_visibility_closed: false,
            pending: None,
            pending_parts: Vec::new(),
            closed: None,
            verified: None,
            source,
        })
    }

    pub(super) fn validate(&self, head: &Head, config: &Config) -> Result<()> {
        self.validate_shape(head)?;
        ensure!(
            self.configuration == digest(config)?,
            "retained stage policy differs"
        );
        config.domain(&self.context)?;
        if let Some(source) = &self.source {
            ensure!(
                source.configuration == self.configuration,
                "destination source policy changed"
            );
        }
        Ok(())
    }

    pub(in crate::external_object) fn validate_shape(&self, head: &Head) -> Result<()> {
        self.context.validate()?;
        ensure!(
            digest_string(&self.configuration)
                && self.context.scope(self.destination)? == head.scope,
            "retained stage domain differs"
        );
        ensure!(
            self.frozen_parts <= self.context.intent.part_count()?
                && self.grant_count <= 100_000
                && head.incarnation.get() <= MAX_INCARNATION,
            "retained stage count invalid"
        );
        if let Some(turn) = &self.pending {
            turn.intent.validate()?;
            let expected = if creates_visible(&turn.intent.operation, &self.context) {
                head.incarnation
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("retained incarnation overflow"))?
            } else {
                head.incarnation.get()
            };
            ensure!(
                turn.intent.context == self.context
                    && turn.intent.scope()? == head.scope
                    && digest_string(&turn.dispatch_nonce)
                    && turn.expected_incarnation.get() == expected
                    && expected <= MAX_INCARNATION,
                "retained stage turn differs"
            );
        }
        ensure!(
            self.pending_parts.len() <= 64
                && (self.pending_parts.is_empty()
                    || (self.destination
                        && self.phase == Phase::DestinationActive
                        && self.pending.is_none())),
            "concurrent part ownership shape invalid"
        );
        let mut previous = 0;
        for part in &self.pending_parts {
            ensure!(
                part.part_number > previous
                    && part.part_number <= self.context.intent.part_count()?
                    && super::super::protocol::id(&part.operation_id)
                    && digest_string(&part.intent_digest)
                    && digest_string(&part.dispatch_nonce)
                    && part.expected_incarnation == head.incarnation,
                "corrupt concurrent part reference"
            );
            previous = part.part_number;
        }
        for reference in [&self.closed, &self.verified].into_iter().flatten() {
            ensure!(
                super::super::protocol::id(&reference.operation_id)
                    && digest_string(&reference.digest),
                "corrupt stage receipt reference"
            );
        }
        ensure!(
            self.verified.is_none() || self.closed.is_some(),
            "verified stage without closure"
        );
        ensure!(
            !self.upload_id_visibility_closed
                || matches!(self.phase, Phase::Closed | Phase::Verified | Phase::Aborted),
            "provider visibility falsely closed"
        );
        if self.destination {
            let source = self
                .source
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("destination lost immutable source"))?;
            source.validate(&self.context, &digest(&source.verified)?)?;
        } else {
            ensure!(
                self.source.is_none(),
                "stage unexpectedly owns destination proof"
            );
        }
        if matches!(
            self.phase,
            Phase::Active | Phase::Freezing | Phase::Frozen | Phase::DestinationActive
        ) {
            ensure!(
                self.upload_id
                    .as_ref()
                    .is_some_and(|id| !id.is_empty() && id.len() <= 1024),
                "active stage lost provider session"
            );
        }
        if matches!(self.phase, Phase::Closed | Phase::Verified) {
            ensure!(
                self.closed.is_some() && self.upload_id_visibility_closed,
                "closed stage lacks positive closure"
            );
        }
        if self.phase == Phase::Verified {
            ensure!(self.verified.is_some(), "verified stage receipt absent");
        }
        Ok(())
    }

    fn admits(&self, intent: &Intent) -> Result<()> {
        ensure!(
            intent.context == self.context && intent.operation.destination() == self.destination,
            "multipart owner/context differs"
        );
        let upload_matches = |id: &str| self.upload_id.as_deref() == Some(id);
        ensure!(
            matches!(intent.operation, Operation::CopyDestinationPart { .. })
                || self.pending_parts.is_empty(),
            "unfinished parts block exclusive destination control"
        );
        match &intent.operation {
            Operation::CreateStage | Operation::CreateDestination { .. } => ensure!(
                self.phase == Phase::Creating && self.upload_id.is_none(),
                "provider session already created"
            ),
            Operation::RegisterParts { upload_id, .. } => ensure!(
                !self.destination && self.phase == Phase::Active && upload_matches(upload_id),
                "part grant admission closed"
            ),
            Operation::FreezeParts {
                upload_id,
                manifest,
                first_part,
                ..
            } => {
                ensure!(
                    !self.destination
                        && matches!(self.phase, Phase::Active | Phase::Freezing)
                        && upload_matches(upload_id)
                        && *first_part == self.frozen_parts + 1,
                    "stage freeze order differs"
                );
                ensure!(
                    self.manifest
                        .as_ref()
                        .is_none_or(|retained| retained == manifest),
                    "frozen manifest commitment changed"
                );
            }
            Operation::CompleteStage {
                upload_id,
                manifest,
            } => ensure!(
                !self.destination
                    && self.phase == Phase::Frozen
                    && upload_matches(upload_id)
                    && self.manifest.as_ref() == Some(manifest),
                "stage completion differs from freeze"
            ),
            Operation::VerifyClosedStage {
                upload_id,
                close_receipt_digest,
            } => ensure!(
                !self.destination
                    && matches!(self.phase, Phase::Closed | Phase::Verified)
                    && self.upload_id == *upload_id
                    && self
                        .closed
                        .as_ref()
                        .is_some_and(|closed| closed.digest == *close_receipt_digest),
                "source closure differs"
            ),
            Operation::AbortStage { upload_id } => ensure!(
                !self.destination
                    && matches!(self.phase, Phase::Active | Phase::Freezing | Phase::Frozen)
                    && upload_matches(upload_id),
                "closed stage cannot be aborted/deleted"
            ),
            Operation::CopyDestinationPart {
                upload_id,
                verified_stage_receipt_digest,
                part,
            } => ensure!(
                self.destination
                    && self.phase == Phase::DestinationActive
                    && upload_matches(upload_id)
                    && part.part_number > 0
                    && part.part_number <= self.context.intent.part_count()?
                    && self
                        .source
                        .as_ref()
                        .is_some_and(|source| digest(&source.verified)
                            .is_ok_and(|value| value == *verified_stage_receipt_digest)),
                "destination copy source/session differs"
            ),
            Operation::CompleteDestination {
                upload_id,
                manifest,
                ..
            } => ensure!(
                self.destination
                    && self.phase == Phase::DestinationActive
                    && upload_matches(upload_id)
                    && self.frozen_parts == self.context.intent.part_count()?
                    && self
                        .manifest
                        .as_ref()
                        .is_none_or(|retained| retained == manifest),
                "destination complete manifest differs"
            ),
            Operation::AbortDestination { upload_id, .. } => ensure!(
                self.destination
                    && self.phase == Phase::DestinationActive
                    && upload_matches(upload_id),
                "destination abort differs"
            ),
        }
        Ok(())
    }
}

/// Checks recovery eligibility without allocating a turn or proving permission.
/// Begin repeats this against the retained head after all storage awaits.
pub(super) fn recovery_read(
    head: &Head,
    object: &ObjectConfig,
    config: &Config,
    intent: &Intent,
    closed: &Receipt,
) -> Result<Turn> {
    head.validate(object, &intent.scope()?)?;
    intent.validate()?;
    ensure!(
        intent.operation.immutable_read(),
        "recovery requires immutable verification"
    );
    let session = head
        .stage
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("recovery lacks retained session"))?;
    session.validate(head, config)?;
    session.admits(intent)?;
    ensure!(
        head.pending.is_none()
            && session.pending_parts.is_empty()
            && !session.destination
            && session.context == intent.context,
        "recovery conflicts with retained owner"
    );
    let pending = session
        .pending
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("recovery lacks exact pending read"))?;
    ensure!(pending.intent == *intent, "recovery changed retained read");
    closed.validate()?;
    let reference = session
        .closed
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("recovery lacks positive closure"))?;
    ensure!(
        closed.turn.intent.context == intent.context
            && reference.operation_id == closed.turn.intent.operation_id
            && reference.digest == digest(closed)?,
        "recovery changed positive closure"
    );
    let stamp = match (&closed.turn.intent.operation, &closed.outcome) {
        (
            Operation::CompleteStage {
                upload_id,
                manifest,
            },
            Outcome::Closed { guard_stamp, .. },
        ) => {
            ensure!(
                session.upload_id.as_ref() == Some(upload_id)
                    && session.manifest.as_ref() == Some(manifest),
                "recovery changed frozen source"
            );
            guard_stamp
        }
        (Operation::CreateStage, Outcome::EmptyClosed { guard_stamp, .. }) => guard_stamp,
        _ => anyhow::bail!("recovery requires positive immutable stage closure"),
    };
    ensure!(
        stamp.physical_authority_id == head.scope.physical_authority_id
            && stamp.incarnation.as_str() == head.incarnation.get().to_string()
            && pending.expected_incarnation == head.incarnation,
        "recovery changed closed source incarnation"
    );
    Ok(pending.clone())
}

pub(super) fn begin(
    head: &Head,
    object: &ObjectConfig,
    config: &Config,
    intent: Intent,
    admission_mode: ExternalStageAdmissionMode,
    recovery_closed: Option<&Receipt>,
    write_lease: &[u8],
    read_lease: &[u8],
    nonce: String,
    source: Option<SourceProof>,
    retained_part_turn: Option<Turn>,
    clock: LeaseClock,
) -> Result<(Head, Turn)> {
    head.validate(object, &intent.scope()?)?;
    intent.validate()?;
    let domain = config.domain(&intent.context)?;
    match admission_mode {
        ExternalStageAdmissionMode::Fresh => ensure!(
            clock.observed_at < i64::try_from(intent.context.logical_expires_at.get())?,
            "original logical stage eligibility expired"
        ),
        ExternalStageAdmissionMode::ResumeImmutableRead => {
            ensure!(
                source.is_none() && retained_part_turn.is_none(),
                "read recovery cannot introduce a destination source or part"
            );
            let closed = recovery_closed
                .ok_or_else(|| anyhow::anyhow!("recovery lacks retained closure"))?;
            let retained = recovery_read(head, object, config, &intent, closed)?;
            ensure!(
                retained.dispatch_nonce == nonce,
                "recovery allocated a different nonce"
            );
        }
    }
    ensure!(
        head.pending.is_none()
            && head.observation.is_none()
            && head.receipts.get() < MAX_RECEIPTS
            && digest_string(&nonce),
        "prior object effect or journal capacity blocks stage"
    );
    // Refuse Create before allocating a provider UploadId that could never be
    // published with a fresh permanent incarnation.
    ensure!(
        !matches!(
            intent.operation,
            Operation::CreateStage | Operation::CreateDestination { .. }
        ) || head.incarnation.get() < MAX_INCARNATION,
        "guard incarnation capacity exhausted"
    );
    let mut session = match &head.stage {
        Some(session) => session.clone(),
        None => Box::new(Session::initialize(config, &intent, source.clone())?),
    };
    if session.destination {
        if let Some(proof) = source {
            let prior = session
                .source
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("destination source absent"))?;
            proof.validate(&intent.context, &digest(&prior.verified)?)?;
            ensure!(
                proof.closed == prior.closed
                    && proof.verified == prior.verified
                    && proof.configuration == session.configuration,
                "immutable destination source changed"
            );
            session.source = Some(proof);
        }
    }
    session.validate(head, config)?;
    session.admits(&intent)?;
    let part_number = match &intent.operation {
        Operation::CopyDestinationPart { part, .. } => Some(part.part_number),
        _ => None,
    };
    let part_reference = part_number.and_then(|number| {
        session
            .pending_parts
            .iter()
            .find(|pending| pending.part_number == number)
    });
    let part_already_pending = part_reference.is_some();
    let resumed_part = if let Some(reference) = part_reference {
        let retained = retained_part_turn
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pending part lost exact durable turn"))?;
        ensure!(
            retained.intent == intent && PartTurnRef::from_turn(retained)? == *reference,
            "unknown part effect differs from retained exact bytes/owner"
        );
        Some(retained.clone())
    } else {
        ensure!(
            retained_part_turn.is_none(),
            "part turn exists without matching pending reference"
        );
        ensure!(
            part_number.is_none() || session.pending_parts.len() < 64,
            "concurrent destination part bound reached"
        );
        None
    };
    let resumed = session
        .pending
        .as_ref()
        .map(|pending| {
            ensure!(
                pending.intent == intent,
                "unknown stage effect blocks other controls"
            );
            ensure!(
                intent.operation.immutable_read(),
                "unknown mutation permit cannot be reissued"
            );
            // Immutable source reads and private identical-range copies cannot
            // mutate the closed source. Destination remains owned/private; successful
            // provider Complete/Abort closes its UploadId against all late copies.
            ensure!(
                domain
                    .provider_contract
                    .completed_upload_id_rejects_late_parts,
                "retry requires qualified closed provider session semantics"
            );
            Ok::<_, anyhow::Error>(pending.clone())
        })
        .transpose()?;
    let (cohort, lease, effect) = if intent.operation.immutable_read() {
        (&domain.read_cohort, read_lease, LeaseEffect::Read)
    } else {
        (
            &domain.write_cohort,
            write_lease,
            effect(
                &intent.operation,
                intent.context.intent.byte_size.get() == 0,
            ),
        )
    };
    let validated = object.verifier()?.validate_lease(
        lease,
        cohort,
        &object.timing_profile,
        &head.floor,
        &head.scope.full_key,
        effect,
        clock,
    )?;
    let mut next = head.clone();
    next.floor = validated.next_floor;
    let expected_incarnation = if creates_visible(&intent.operation, &intent.context) {
        let value = head
            .incarnation
            .get()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("guard incarnation exhausted"))?;
        GuardIncarnation::parse(value.to_string())?;
        WireInteger::new(value)
    } else {
        head.incarnation
    };
    ensure!(
        resumed.is_none() || part_number.is_none(),
        "exclusive turn blocks concurrent part"
    );
    if resumed_part.is_some() {
        ensure!(
            domain
                .provider_contract
                .completed_upload_id_rejects_late_parts
                && domain
                    .provider_contract
                    .multipart_copy_from_immutable_source,
            "exact part retry requires qualified immutable provider semantics"
        );
    }
    let turn = resumed.or(resumed_part).unwrap_or(Turn {
        intent,
        dispatch_nonce: nonce,
        expected_incarnation,
    });
    if part_number.is_some() {
        ensure!(
            session.pending.is_none(),
            "exclusive destination mutation blocks parts"
        );
        let reference = PartTurnRef::from_turn(&turn)?;
        if !part_already_pending {
            let index = session
                .pending_parts
                .partition_point(|part| part.part_number < reference.part_number);
            session.pending_parts.insert(index, reference);
        }
    } else {
        session.pending = Some(turn.clone());
    }
    next.stage = Some(session);
    Ok((next, turn))
}

pub(super) fn terminal(head: &Head, config: &Config, receipt: &Receipt) -> Result<Head> {
    receipt.validate()?;
    let mut session = head
        .stage
        .clone()
        .ok_or_else(|| anyhow::anyhow!("stage terminal without session"))?;
    session.validate(head, config)?;
    let copied = matches!(receipt.outcome, Outcome::Copied { .. });
    let part_reference = if copied {
        Some(PartTurnRef::from_turn(&receipt.turn)?)
    } else {
        None
    };
    if let Some(reference) = &part_reference {
        ensure!(
            session
                .pending_parts
                .iter()
                .any(|pending| pending == reference),
            "part terminal differs from exact pending"
        );
    } else {
        ensure!(
            session.pending.as_ref() == Some(&receipt.turn) && session.pending_parts.is_empty(),
            "stage terminal differs from exclusive pending"
        );
    }
    let mut next = head.clone();
    let reference = ReceiptRef {
        operation_id: receipt.turn.intent.operation_id.clone(),
        digest: digest(receipt)?,
    };
    match &receipt.outcome {
        Outcome::Created { upload_id } => {
            session.upload_id = Some(upload_id.clone());
            session.phase = if session.destination {
                Phase::DestinationActive
            } else {
                Phase::Active
            };
        }
        Outcome::Registered => {
            let Operation::RegisterParts { grants, .. } = &receipt.turn.intent.operation else {
                anyhow::bail!("grant receipt shape differs");
            };
            for grant in grants {
                session.grant_horizon = session.grant_horizon.max(grant.expires_at);
            }
        }
        Outcome::Frozen { part_count } => {
            let Operation::FreezeParts { manifest, .. } = &receipt.turn.intent.operation else {
                anyhow::bail!("freeze receipt shape differs");
            };
            session.manifest = Some(manifest.clone());
            session.frozen_parts = *part_count;
            session.phase = if *part_count == session.context.intent.part_count()? {
                Phase::Frozen
            } else {
                Phase::Freezing
            };
        }
        Outcome::Closed { .. } | Outcome::EmptyClosed { .. } => {
            next.incarnation = receipt.turn.expected_incarnation;
            session.phase = Phase::Closed;
            session.upload_id_visibility_closed = true;
            session.closed = Some(reference.clone());
            if session.destination {
                next.visible_receipt = Some(VisibleReceipt {
                    kind: VisibleKind::DestinationClose,
                    operation_id: reference.operation_id.clone(),
                    receipt_digest: reference.digest.clone(),
                    context_digest: digest(&session.context)?,
                    incarnation: next.incarnation,
                    stage_configuration: Some(session.configuration.clone()),
                });
            }
        }
        Outcome::Verified { .. } => {
            session.phase = Phase::Verified;
            session.verified = Some(reference);
        }
        Outcome::Copied { part, .. } => {
            part.validate(&session.context.intent)?;
            session.frozen_parts = session
                .frozen_parts
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("destination part count overflow"))?;
            ensure!(
                session.frozen_parts <= session.context.intent.part_count()?,
                "destination part count exceeds source"
            );
        }
        // Positive Abort closes visibility for this UploadId. It proves neither
        // drain nor physical reclamation of late part I/O; grant horizons and
        // every retained descriptor/receipt remain cleanup obligations.
        Outcome::Aborted { .. } => {
            session.phase = Phase::Aborted;
            session.upload_id_visibility_closed = true;
        }
    }
    if let Some(reference) = part_reference {
        session.pending_parts.retain(|part| part != &reference);
    } else {
        session.pending = None;
    }
    next.receipts = LeaseInteger::new(
        head.receipts
            .get()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("stage receipt count exhausted"))?,
    )?;
    ensure!(
        next.receipts.get() <= MAX_RECEIPTS,
        "stage receipt capacity exhausted"
    );
    next.stage = if session.destination && matches!(session.phase, Phase::Closed | Phase::Aborted) {
        None
    } else {
        Some(session)
    };
    Ok(next)
}

pub(super) fn effect(operation: &Operation, empty: bool) -> LeaseEffect {
    match operation {
        Operation::CreateStage | Operation::CreateDestination { .. } if empty => LeaseEffect::Put,
        Operation::CreateStage | Operation::CreateDestination { .. } => {
            LeaseEffect::MultipartCreate
        }
        Operation::RegisterParts { .. } | Operation::CopyDestinationPart { .. } => {
            LeaseEffect::MultipartPart
        }
        Operation::FreezeParts { .. }
        | Operation::CompleteStage { .. }
        | Operation::CompleteDestination { .. } => LeaseEffect::MultipartComplete,
        Operation::VerifyClosedStage { .. } => LeaseEffect::Read,
        Operation::AbortStage { .. } | Operation::AbortDestination { .. } => {
            LeaseEffect::MultipartAbort
        }
    }
}

fn creates_visible(operation: &Operation, context: &ExternalStageContext) -> bool {
    matches!(
        operation,
        Operation::CompleteStage { .. } | Operation::CompleteDestination { .. }
    ) || (context.intent.byte_size.get() == 0
        && matches!(
            operation,
            Operation::CreateStage | Operation::CreateDestination { .. }
        ))
}

pub(super) fn replay(
    head: &Head,
    config: &Config,
    intent: &Intent,
    receipt: &Receipt,
) -> Result<Head> {
    receipt.validate()?;
    ensure!(
        receipt.turn.intent == *intent,
        "stage retained effect identity changed"
    );
    let mut next = head.clone();
    if let Some(session) = &head.stage {
        session.validate(head, config)?;
        if matches!(receipt.outcome, Outcome::Copied { .. }) {
            let reference = PartTurnRef::from_turn(&receipt.turn)?;
            next.stage
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("part replay lost session"))?
                .pending_parts
                .retain(|part| part != &reference);
        }
        if session.pending.as_ref() == Some(&receipt.turn) {
            next.stage
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("stage replay lost session"))?
                .pending = None;
        }
    }
    Ok(next)
}
