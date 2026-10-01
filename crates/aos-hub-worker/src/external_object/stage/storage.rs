//! Atomic compact stage ownership on the same permanent physical-key object.
//!
//! The object never calls the provider. Every outward mutation is preceded by a
//! retained turn; terminal receipt and matching pending clear share one SQLite
//! transaction. Part grants retain their original identity and horizons.
//!
//! ```text
//! external-stage/receipt/v1/<operation digest> -> immutable receipt string
//! external-stage/part/v1/<context digest>/<part> -> immutable part/freeze record
//! external-stage/grant/v1/<context digest>/<grant digest> -> exact grant string
//! ```

use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{DirectManifestPart, WireInteger};
use aos_hub_core::storage_authority::{
    external_object::stage::{
        ExternalStageAdmissionMode, ExternalStageOperation, ExternalStageOutcome,
    },
    lease::{EpochLeaseFloor, LeaseEffect, LeaseInteger},
};
use rand::TryRngCore as _;
use worker::{Method, Request, Response, Storage};

use super::super::{
    config::{configured, Config as ObjectConfig},
    protocol::{digest, GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER},
    state::Head,
    storage::{
        decode, error, key, load_head, transaction_string, ExternalObjectGuard, BINDING, HEAD,
    },
};
use super::{
    config,
    protocol::{self, Intent, Operation, Receipt, Reply, SourceProof},
    state::{self, PartRecord},
};

const MAX_GRANTS: u32 = 100_000;

async fn recovery_closed(storage: &Storage, head: &Head) -> Result<Receipt> {
    let reference = head
        .stage
        .as_ref()
        .and_then(|session| session.closed.as_ref())
        .ok_or_else(|| anyhow::anyhow!("recovery lacks positive closure reference"))?;
    load_receipt(storage, &reference.operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("recovery lost positive closure receipt"))
}

impl ExternalObjectGuard {
    pub(crate) async fn stage_fetch(&self, request: &mut Request) -> worker::Result<Response> {
        match self.stage_handle(request).await {
            Ok(reply) => {
                let encoded = serde_json::to_string(&reply).map_err(error)?;
                if encoded.len() > MAX_MESSAGE {
                    return Response::error("external stage turn refused", 409);
                }
                let headers = worker::Headers::new();
                headers.set("content-type", "application/json")?;
                headers.set("cache-control", "private, no-store")?;
                Ok(Response::ok(encoded)?.with_headers(headers))
            }
            Err(_) => Response::error("external stage turn refused", 409),
        }
    }

    async fn stage_handle(&self, request: &mut Request) -> Result<Reply> {
        ensure!(
            request.method() == Method::Post,
            "invalid stage journal method"
        );
        let bytes = crate::hybrid::read_bounded_body(request, MAX_MESSAGE)
            .await?
            .ok_or_else(|| anyhow::anyhow!("stage journal request oversized"))?;
        let signature = request
            .headers()
            .get(GUARD_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("stage journal signature missing"))?;
        let message = protocol::authenticated(&key(&self.env)?, &signature, &bytes)?;
        let object =
            configured(&self.env)?.ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
        let config = config::configured(&self.env, &object)?
            .ok_or_else(|| anyhow::anyhow!("external stage consumer disabled"))?;
        let name = message.scope.guard_name()?;
        ensure!(
            message.scope.guard_namespace_id == object.guard_namespace_id
                && request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str()),
            "stage guard differs from configured namespace"
        );
        ensure!(
            self.env
                .durable_object(BINDING)?
                .id_from_name(&name)?
                .to_string()
                == self.state.id().to_string(),
            "stage request addressed to another guard"
        );

        let _gate = self.gate.lock().await;
        let storage = self.state.storage();
        let prior = load_head(&storage).await?;
        match message.operation {
            Operation::Delegation {
                intent,
                write_lease,
            } => {
                intent.validate()?;
                ensure!(
                    intent.scope()? == message.scope
                        && matches!(
                            intent.operation,
                            ExternalStageOperation::RegisterParts { .. }
                        ),
                    "delegation context differs"
                );
                let head = prior
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("delegation lacks retained owner"))?;
                head.validate(&object, &message.scope)?;
                let session = head
                    .stage
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("delegation lacks stage session"))?;
                session.validate(head, &config)?;
                ensure!(
                    head.pending.is_none()
                        && head.observation.is_none()
                        && session.pending.is_none()
                        && session.context == intent.context
                        && !session.destination
                        && session.phase == state::Phase::Active,
                    "delegated grant admission closed"
                );
                let receipt = load_receipt(&storage, &intent.operation_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("grant registration receipt absent"))?;
                ensure!(
                    receipt.turn.intent == intent
                        && receipt.outcome == ExternalStageOutcome::Registered,
                    "delegation does not match retained registration"
                );
                let domain = config.domain(&intent.context)?;
                ensure!(
                    object.clock().observed_at
                        < i64::try_from(intent.context.logical_expires_at.get())?,
                    "original delegation eligibility expired"
                );
                let validated = object.verifier()?.validate_lease(
                    write_lease.as_bytes(),
                    &domain.write_cohort,
                    &object.timing_profile,
                    &head.floor,
                    &message.scope.full_key,
                    LeaseEffect::MultipartPart,
                    object.clock(),
                )?;
                let mut next = head.clone();
                next.floor = validated.next_floor;
                let floor = next.floor.clone();
                commit(&storage, prior, next, BTreeMap::new()).await?;
                Ok(Reply::Delegation { receipt, floor })
            }
            Operation::Lookup { intent } => {
                intent.validate()?;
                config.domain(&intent.context)?;
                ensure!(
                    intent.scope()? == message.scope,
                    "stage lookup scope changed"
                );
                let receipt = load_receipt(&storage, &intent.operation_id).await?;
                if let Some(receipt) = receipt {
                    let head = prior
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("stage receipt without head"))?;
                    head.validate(&object, &message.scope)?;
                    let next = state::replay(head, &config, &intent, &receipt)?;
                    commit(&storage, prior, next, BTreeMap::new()).await?;
                    Ok(Reply::Terminal { receipt })
                } else {
                    // Absence is not proof that an effect settled or was never
                    // dispatched. Begin must still examine retained pending.
                    Ok(Reply::Unsettled)
                }
            }
            Operation::RecoveryRead { intent } => {
                ensure!(intent.scope()? == message.scope, "recovery scope changed");
                let head = prior
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("recovery lacks retained head"))?;
                let closed = recovery_closed(&storage, head).await?;
                let turn = state::recovery_read(head, &object, &config, &intent, &closed)?;
                // This read-only projection allocates no permit and changes no floor.
                Ok(Reply::RecoveryRead {
                    turn,
                    floor: head.floor.clone(),
                })
            }
            Operation::Begin {
                admission_mode,
                intent,
                write_lease,
                read_lease,
                source,
            } => {
                intent.validate()?;
                let existing = load_receipt(&storage, &intent.operation_id).await?;
                // This provider contract proves multipart Abort, but does not
                // prove an exact-incarnation empty-object deletion receipt.
                // Refuse new empty effects before retaining or dispatching Put.
                ensure!(
                    existing.is_some()
                        || intent.context.intent.byte_size.get() != 0
                        || !matches!(
                            intent.operation,
                            ExternalStageOperation::CreateStage
                                | ExternalStageOperation::CreateDestination { .. }
                        ),
                    "external empty-object deletion is not qualified"
                );
                let direct_permission_expires_at = crate::direct_guard::check_external_stage(
                    &storage,
                    &intent.operation_id,
                    &intent.context,
                    &intent.operation,
                    existing.is_some(),
                )
                .await?;
                ensure!(
                    intent.scope()? == message.scope,
                    "stage begin scope changed"
                );
                let head = match &prior {
                    Some(head) => head.clone(),
                    None => {
                        ensure!(
                            admission_mode == ExternalStageAdmissionMode::Fresh,
                            "recovery cannot initialize a head"
                        );
                        ensure!(existing.is_none(), "stage receipt without head");
                        initialize(&object, &config, &intent)?
                    }
                };
                head.validate(&object, &message.scope)?;
                if let Some(receipt) = existing {
                    let next = state::replay(&head, &config, &intent, &receipt)?;
                    commit(&storage, prior, next, BTreeMap::new()).await?;
                    return Ok(Reply::Terminal { receipt });
                }

                let mut changes = BTreeMap::new();
                if matches!(
                    intent.operation,
                    ExternalStageOperation::CreateDestination { .. }
                ) && head.stage.is_none()
                {
                    let owner_key = format!(
                        "external-stage/destination-owner/v1/{}",
                        intent.context.fingerprint()?
                    );
                    let expected = raw(&storage, &owner_key).await?;
                    ensure!(
                        expected.is_none(),
                        "destination owner context was already used"
                    );
                    changes.insert(
                        owner_key,
                        Change {
                            expected,
                            next: encoded(&intent.operation_id)?,
                        },
                    );
                }
                let retained_part =
                    if let ExternalStageOperation::CopyDestinationPart { part, .. } =
                        &intent.operation
                    {
                        ensure!(
                            raw(&storage, &part_key(&intent, part.part_number)?)
                                .await?
                                .is_none(),
                            "destination part already has a positive receipt"
                        );
                        decode(
                            raw(&storage, &part_turn_key(&intent, part.part_number)?).await?,
                            MAX_MESSAGE,
                        )?
                    } else {
                        None
                    };
                let metadata =
                    prepare_metadata(&storage, &intent, &config, &head, &mut changes).await?;
                let closed = if admission_mode == ExternalStageAdmissionMode::ResumeImmutableRead {
                    Some(recovery_closed(&storage, &head).await?)
                } else {
                    None
                };
                let nonce = if let Some(closed) = &closed {
                    state::recovery_read(&head, &object, &config, &intent, closed)?.dispatch_nonce
                } else {
                    let mut nonce = [0_u8; 32];
                    rand::rngs::OsRng
                        .try_fill_bytes(&mut nonce)
                        .map_err(|_| anyhow::anyhow!("stage dispatch randomness unavailable"))?;
                    hex::encode(nonce)
                };
                // All part/receipt storage awaits precede this clock observation.
                let (mut next, turn) = state::begin(
                    &head,
                    &object,
                    &config,
                    intent,
                    admission_mode,
                    closed.as_ref(),
                    write_lease.as_bytes(),
                    read_lease.as_bytes(),
                    nonce,
                    source,
                    retained_part,
                    object.clock(),
                )?;
                if let Some((outcome, new_grants)) = metadata {
                    let receipt = Receipt { turn, outcome };
                    next = state::terminal(&next, &config, &receipt)?;
                    let session = next
                        .stage
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("metadata lost stage session"))?;
                    session.grant_count = session
                        .grant_count
                        .checked_add(new_grants)
                        .ok_or_else(|| anyhow::anyhow!("stage grant count exhausted"))?;
                    ensure!(
                        session.grant_count <= MAX_GRANTS,
                        "stage grant capacity exhausted"
                    );
                    add_receipt(&storage, &receipt, &mut changes).await?;
                    // Metadata has no outward provider effect. Its exact records,
                    // floor and terminal receipt commit together before any URL.
                    commit(&storage, prior, next, changes).await?;
                    return Ok(Reply::Terminal { receipt });
                }
                if let ExternalStageOperation::CopyDestinationPart { part, .. } =
                    &turn.intent.operation
                {
                    let key = part_turn_key(&turn.intent, part.part_number)?;
                    let expected = raw(&storage, &key).await?;
                    let serialized = encoded(&turn)?;
                    ensure!(
                        expected
                            .as_ref()
                            .is_none_or(|retained| retained == &serialized),
                        "retained destination part turn changed"
                    );
                    changes.insert(
                        key,
                        Change {
                            expected,
                            next: serialized,
                        },
                    );
                }
                let floor = next.floor.clone();
                let source = next.stage.as_ref().and_then(|stage| stage.source.clone());
                commit(&storage, prior, next, changes).await?;
                Ok(Reply::Dispatch {
                    turn,
                    floor,
                    source,
                    direct_permission_expires_at,
                })
            }
            Operation::Terminal { receipt } => {
                receipt.validate()?;
                ensure!(
                    receipt.turn.intent.scope()? == message.scope,
                    "stage terminal scope changed"
                );
                let head = prior
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("stage terminal without head"))?;
                head.validate(&object, &message.scope)?;
                let existing = load_receipt(&storage, &receipt.turn.intent.operation_id).await?;
                let replayed = existing.is_some();
                let next = if let Some(existing) = existing {
                    ensure!(existing == receipt, "stage terminal receipt changed");
                    state::replay(head, &config, &receipt.turn.intent, &receipt)?
                } else {
                    state::terminal(head, &config, &receipt)?
                };
                let mut changes = BTreeMap::new();
                if let ExternalStageOutcome::Copied { part, etag } = &receipt.outcome {
                    if !replayed {
                        let record_key = part_key(&receipt.turn.intent, part.part_number)?;
                        let expected = raw(&storage, &record_key).await?;
                        ensure!(
                            expected.is_none(),
                            "destination copied part already differs"
                        );
                        let record = PartRecord {
                            part: part.clone(),
                            highest_grant_revision: WireInteger::new(0),
                            grant_horizon: WireInteger::new(0),
                            frozen: Some(DirectManifestPart {
                                part: part.clone(),
                                etag: etag.clone(),
                            }),
                        };
                        changes.insert(
                            record_key,
                            Change {
                                expected,
                                next: encoded(&record)?,
                            },
                        );
                    }
                }
                add_receipt(&storage, &receipt, &mut changes).await?;
                commit(&storage, prior, next, changes).await?;
                Ok(Reply::Terminal { receipt })
            }
            Operation::ManifestPage {
                turn,
                first_part,
                limit,
            } => {
                turn.intent.validate()?;
                ensure!(
                    turn.intent.scope()? == message.scope
                        && first_part > 0
                        && limit > 0
                        && limit <= protocol::MAX_PART_PAGE,
                    "invalid stage manifest page"
                );
                let head = prior
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("manifest without stage head"))?;
                head.validate(&object, &message.scope)?;
                let session = head
                    .stage
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("manifest session absent"))?;
                session.validate(head, &config)?;
                ensure!(
                    session.pending.as_ref() == Some(&turn)
                        && matches!(
                            turn.intent.operation,
                            ExternalStageOperation::CompleteStage { .. }
                                | ExternalStageOperation::CompleteDestination { .. }
                                | ExternalStageOperation::VerifyClosedStage { .. }
                        ),
                    "manifest lacks exact retained turn"
                );
                let count = turn.intent.context.intent.part_count()?;
                let end = first_part.saturating_add(limit - 1).min(count);
                ensure!(
                    first_part <= count || (count == 0 && first_part == 1),
                    "manifest page outside source"
                );
                let mut parts = Vec::new();
                for number in first_part..=end {
                    let record: PartRecord = decode(
                        raw(&storage, &part_key(&turn.intent, number)?).await?,
                        MAX_MESSAGE,
                    )?
                    .ok_or_else(|| anyhow::anyhow!("retained manifest part absent"))?;
                    let part = record
                        .frozen
                        .ok_or_else(|| anyhow::anyhow!("retained part not frozen"))?;
                    part.part.validate(&turn.intent.context.intent)?;
                    ensure!(
                        part.part.part_number == number,
                        "retained part number changed"
                    );
                    parts.push(part);
                }
                Ok(Reply::ManifestPage {
                    parts,
                    next_part: (end < count).then_some(end + 1),
                })
            }
            Operation::SourceProof {
                context,
                receipt_digest,
                part_number,
                read_lease,
            } => {
                context.validate()?;
                ensure!(
                    context.scope(false)? == message.scope,
                    "source proof scope changed"
                );
                let head = prior
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("source proof without head"))?;
                head.validate(&object, &message.scope)?;
                let session = head
                    .stage
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("source stage absent"))?;
                session.validate(head, &config)?;
                ensure!(
                    head.pending.is_none()
                        && head.observation.is_none()
                        && session.pending.is_none()
                        && session.context == context
                        && !session.destination
                        && session.phase == state::Phase::Verified,
                    "source observation blocked"
                );
                let closed_ref = session
                    .closed
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("source closure absent"))?;
                let verified_ref = session
                    .verified
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("source verification absent"))?;
                let closed = load_receipt(&storage, &closed_ref.operation_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("source close receipt absent"))?;
                let verified = load_receipt(&storage, &verified_ref.operation_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("source verification receipt absent"))?;
                ensure!(
                    digest(&closed)? == closed_ref.digest
                        && digest(&verified)? == verified_ref.digest
                        && verified_ref.digest == receipt_digest,
                    "source immutable receipt differs"
                );
                let part = if let Some(number) = part_number {
                    ensure!(
                        number > 0 && number <= context.intent.part_count()?,
                        "source part number invalid"
                    );
                    let key = format!(
                        "external-stage/part/v1/{}/{number:05}",
                        context.fingerprint()?
                    );
                    let record: PartRecord = decode(raw(&storage, &key).await?, MAX_MESSAGE)?
                        .ok_or_else(|| anyhow::anyhow!("verified source part absent"))?;
                    let frozen = record
                        .frozen
                        .ok_or_else(|| anyhow::anyhow!("verified source part not frozen"))?;
                    frozen.part.validate(&context.intent)?;
                    ensure!(
                        frozen.part == record.part && frozen.part.part_number == number,
                        "verified source part differs from original grant"
                    );
                    Some(frozen.part)
                } else {
                    None
                };
                let domain = config.domain(&context)?;
                let validated = object.verifier()?.validate_lease(
                    read_lease.as_bytes(),
                    &domain.read_cohort,
                    &object.timing_profile,
                    &head.floor,
                    &message.scope.full_key,
                    LeaseEffect::Read,
                    object.clock(),
                )?;
                let mut next = head.clone();
                next.floor = validated.next_floor;
                let proof = SourceProof {
                    closed,
                    verified,
                    floor: next.floor.clone(),
                    configuration: session.configuration.clone(),
                };
                proof.validate(&context, &receipt_digest)?;
                commit(&storage, prior, next, BTreeMap::new()).await?;
                Ok(Reply::SourceProof { proof, part })
            }
        }
    }
}

fn initialize(object: &ObjectConfig, config: &config::Config, intent: &Intent) -> Result<Head> {
    let domain = config.domain(&intent.context)?;
    let scope = intent.scope()?;
    let floor = EpochLeaseFloor::initialize_fresh_guard(
        domain.write_cohort.authority.clone(),
        object.executor_identity.clone(),
        scope.full_key.clone(),
        &object.timing_profile,
        object.clock(),
    )?;
    Ok(Head {
        version: 1,
        scope,
        configuration: digest(object)?,
        floor,
        pending: None,
        observation: None,
        visible_receipt: None,
        receipts: LeaseInteger::new(0)?,
        incarnation: WireInteger::new(0),
        stage: None,
    })
}

#[derive(Clone)]
struct Change {
    expected: Option<String>,
    next: String,
}

async fn prepare_metadata(
    storage: &Storage,
    intent: &Intent,
    config: &config::Config,
    head: &Head,
    changes: &mut BTreeMap<String, Change>,
) -> Result<Option<(ExternalStageOutcome, u32)>> {
    let domain = config.domain(&intent.context)?;
    match &intent.operation {
        ExternalStageOperation::RegisterParts { grants, .. } => {
            let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
            let mut created = 0_u32;
            for grant in grants {
                ensure!(
                    grant.issued_at.get() <= now.saturating_add(5)
                        && now < grant.expires_at.get()
                        && grant.expires_at <= intent.context.logical_expires_at
                        && grant.expires_at.get() - grant.issued_at.get()
                            <= domain.maximum_grant_lifetime.get(),
                    "delegated grant exceeds configured horizon"
                );
                ensure!(
                    grant.part.checksum.algorithm == intent.context.placement.checksum_algorithm,
                    "grant checksum differs from qualified provider"
                );
                let grant_key = format!(
                    "external-stage/grant/v1/{}/{}",
                    intent.context.fingerprint()?,
                    digest(&grant.grant_id)?
                );
                let expected = raw(storage, &grant_key).await?;
                let next = encoded(grant)?;
                ensure!(
                    expected.as_ref().is_none_or(|prior| prior == &next),
                    "retained grant identity changed"
                );
                let new_grant = expected.is_none();
                if new_grant {
                    created = created
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("grant count overflow"))?;
                }
                changes.insert(grant_key, Change { expected, next });
                let part_key = part_key(intent, grant.part.part_number)?;
                let expected = if let Some(change) = changes.get(&part_key) {
                    change.expected.clone()
                } else {
                    raw(storage, &part_key).await?
                };
                let current = changes
                    .get(&part_key)
                    .map(|change| change.next.clone())
                    .or_else(|| expected.clone());
                let mut record: PartRecord = decode(current, MAX_MESSAGE)?.unwrap_or(PartRecord {
                    part: grant.part.clone(),
                    highest_grant_revision: WireInteger::new(0),
                    grant_horizon: WireInteger::new(0),
                    frozen: None,
                });
                ensure!(
                    record.part == grant.part && record.frozen.is_none(),
                    "part descriptor already changed/frozen"
                );
                // Only an exact retained capability can replay an old revision.
                // A new capability must advance the irreversible part revision.
                ensure!(
                    !new_grant || grant.grant_revision > record.highest_grant_revision,
                    "new grant must advance retained part revision"
                );
                record.highest_grant_revision =
                    record.highest_grant_revision.max(grant.grant_revision);
                record.grant_horizon = record.grant_horizon.max(grant.expires_at);
                changes.insert(
                    part_key,
                    Change {
                        expected,
                        next: encoded(&record)?,
                    },
                );
            }
            ensure!(
                head.stage
                    .as_ref()
                    .map_or(0, |stage| stage.grant_count)
                    .checked_add(created)
                    .is_some_and(|count| count <= MAX_GRANTS),
                "stage grant capacity exhausted"
            );
            Ok(Some((ExternalStageOutcome::Registered, created)))
        }
        ExternalStageOperation::FreezeParts {
            parts, first_part, ..
        } => {
            for member in parts {
                let key = part_key(intent, member.part.part_number)?;
                let expected = raw(storage, &key).await?;
                let mut record: PartRecord = decode(expected.clone(), MAX_MESSAGE)?
                    .ok_or_else(|| anyhow::anyhow!("manifest part was never granted"))?;
                ensure!(
                    record.part == member.part && record.frozen.is_none(),
                    "manifest differs from retained grant"
                );
                record.frozen = Some(member.clone());
                changes.insert(
                    key,
                    Change {
                        expected,
                        next: encoded(&record)?,
                    },
                );
            }
            let count = first_part
                .checked_sub(1)
                .and_then(|n| n.checked_add(parts.len() as u32))
                .ok_or_else(|| anyhow::anyhow!("frozen manifest count overflow"))?;
            Ok(Some((
                ExternalStageOutcome::Frozen { part_count: count },
                0,
            )))
        }
        _ => Ok(None),
    }
}

async fn add_receipt(
    storage: &Storage,
    receipt: &Receipt,
    changes: &mut BTreeMap<String, Change>,
) -> Result<()> {
    let key = receipt_key(&receipt.turn.intent.operation_id)?;
    let expected = raw(storage, &key).await?;
    let next = encoded(receipt)?;
    ensure!(
        expected.as_ref().is_none_or(|prior| prior == &next),
        "stage receipt changed"
    );
    changes.insert(key, Change { expected, next });
    Ok(())
}

pub(super) async fn load_receipt(storage: &Storage, operation: &str) -> Result<Option<Receipt>> {
    let receipt: Option<Receipt> =
        decode(raw(storage, &receipt_key(operation)?).await?, MAX_MESSAGE)?;
    if let Some(receipt) = &receipt {
        receipt.validate()?;
    }
    Ok(receipt)
}

fn receipt_key(operation: &str) -> Result<String> {
    Ok(format!("external-stage/receipt/v1/{}", digest(&operation)?))
}

fn part_key(intent: &Intent, number: u32) -> Result<String> {
    Ok(format!(
        "external-stage/part/v1/{}/{number:05}",
        intent.context.fingerprint()?
    ))
}

fn part_turn_key(intent: &Intent, number: u32) -> Result<String> {
    Ok(format!(
        "external-stage/part-turn/v1/{}/{number:05}",
        intent.context.fingerprint()?
    ))
}

async fn raw(storage: &Storage, key: &str) -> Result<Option<String>> {
    let value = storage.get::<String>(key).await?;
    ensure!(
        value
            .as_ref()
            .is_none_or(|value| value.len() <= MAX_MESSAGE),
        "stage record oversized"
    );
    Ok(value)
}

fn encoded(value: &impl serde::Serialize) -> Result<String> {
    let value = serde_json::to_string(value)?;
    ensure!(
        value.len() <= MAX_MESSAGE,
        "stage record exceeds journal bound"
    );
    Ok(value)
}

async fn commit(
    storage: &Storage,
    expected: Option<Head>,
    next: Head,
    changes: BTreeMap<String, Change>,
) -> Result<()> {
    let next = encoded(&next)?;
    ensure!(
        changes.len() <= 129,
        "stage transaction exceeds record bound"
    );
    storage
        .transaction(move |transaction| {
            let expected = expected.clone();
            let next = next.clone();
            let changes = changes.clone();
            async move {
                let current: Option<Head> =
                    decode(transaction_string(&transaction, HEAD).await?, MAX_MESSAGE)
                        .map_err(error)?;
                if current != expected {
                    return Err(error("stage head CAS refused"));
                }
                for (key, change) in &changes {
                    if transaction_string(&transaction, key).await? != change.expected {
                        return Err(error("stage record CAS refused"));
                    }
                }
                // Each value is an ordinary JSON string, never a JS Map. The
                // transaction persists every record and its head atomically.
                for (key, change) in changes {
                    transaction.put(&key, change.next).await?;
                }
                transaction.put(HEAD, next).await?;
                Ok(())
            }
        })
        .await?;
    Ok(())
}

/// Verifies the actual positive destination closure before new observation.
pub(in crate::external_object) async fn verify_observable_destination(
    env: &worker::Env,
    storage: &Storage,
    head: &Head,
    object: &ObjectConfig,
) -> Result<()> {
    ensure!(
        head.pending.is_none() && head.stage.is_none() && head.observation.is_none(),
        "active physical turn blocks observation"
    );
    let visible = head
        .visible_receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("current positive publication proof absent"))?;
    visible.validate(head)?;
    match visible.kind {
        super::super::state::VisibleKind::MetadataPut => {
            let receipt = super::super::storage::load_receipt(storage, &visible.operation_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("metadata publication receipt absent"))?;
            ensure!(
                receipt.turn.intent.operation_id == visible.operation_id
                    && digest(&receipt)? == visible.receipt_digest
                    && receipt.turn.intent.scope == head.scope
                    && receipt.turn.intent.context == visible.context_digest
                    && matches!(
                        (&receipt.turn.intent.effect, &receipt.outcome),
                        (
                            super::super::protocol::Effect::Put { .. },
                            super::super::protocol::Outcome::PutAcknowledged
                        )
                    ),
                "metadata publication receipt differs"
            );
        }
        super::super::state::VisibleKind::DestinationClose => {
            let config = config::configured(env, object)?
                .ok_or_else(|| anyhow::anyhow!("stage configuration unavailable"))?;
            ensure!(
                visible.stage_configuration.as_ref() == Some(&digest(&config)?),
                "destination configuration differs"
            );
            let receipt = load_receipt(storage, &visible.operation_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("destination close receipt absent"))?;
            receipt.validate()?;
            config.domain(&receipt.turn.intent.context)?;
            ensure!(
                receipt.turn.intent.operation_id == visible.operation_id
                    && digest(&receipt)? == visible.receipt_digest
                    && receipt.turn.intent.scope()? == head.scope
                    && digest(&receipt.turn.intent.context)? == visible.context_digest
                    && receipt.turn.expected_incarnation == head.incarnation
                    && matches!(
                        (&receipt.turn.intent.operation, &receipt.outcome),
                        (
                            ExternalStageOperation::CompleteDestination { .. },
                            ExternalStageOutcome::Closed { .. }
                        ) | (
                            ExternalStageOperation::CreateDestination { .. },
                            ExternalStageOutcome::EmptyClosed { .. }
                        )
                    ),
                "destination closure receipt differs"
            );
        }
    }
    Ok(())
}
