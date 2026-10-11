//! Atomic copy turns and immutable parts on the existing physical-key object.
//!
//! The guard persists pending ownership before returning a one-shot dispatch.
//! A positive receipt and its matching session/head changes commit together.
//! An unknown turn is read-only after restart and never reissued or expired.
//!
//! ```text
//! external-copy/session/v1/<copy_id> -> canonical CopySession string
//! external-copy/receipt/v1/<action_id> -> immutable CopyReceipt string
//! external-copy/part/v1/<copy_id>/<number> -> immutable CopyReceipt string
//! ```

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use aos_hub_core::{
    direct_upload::WireInteger,
    storage_authority::{
        external_object::copy::{
            ExternalCopyOriginal,
            control::CopyControl,
            session::{CopyAction, CopyOutcome, CopyPhase, CopyReceipt, CopySession},
        },
        lease::{EpochLeaseFloor, LeaseEffect, LeaseInteger},
    },
};
use rand::TryRngCore as _;
use worker::{Method, Request as HttpRequest, Response, Storage};

use super::super::{
    config::{Config as ObjectConfig, configured},
    protocol::{GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER, digest},
    state::{Head, MAX_RECEIPTS},
    storage::{
        BINDING, ExternalObjectGuard, HEAD, decode, error, key, load_head, transaction_string,
    },
};
use super::{
    config,
    protocol::{self, Operation, Reply, Request},
    state::Owner,
};

impl ExternalObjectGuard {
    /// Handles separately authenticated private copy turns without provider access.
    ///
    /// # Errors
    /// Returns a bounded refusal for invalid authority, addressing or durable state.
    pub(crate) async fn copy_fetch(&self, request: &mut HttpRequest) -> worker::Result<Response> {
        let result = async {
            ensure!(request.method() == Method::Post, "copy guard requires POST");
            let body = crate::hybrid::read_bounded_body(request, MAX_MESSAGE)
                .await?
                .ok_or_else(|| anyhow::anyhow!("copy guard body oversized"))?;
            let signature = request
                .headers()
                .get(GUARD_HEADER)?
                .ok_or_else(|| anyhow::anyhow!("copy guard authentication absent"))?;
            let guard_key = key(&self.env)?;
            let message = protocol::authenticate(&guard_key, &signature, &body)?;
            let object = configured(&self.env)?
                .ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
            let config = config::configured(&self.env, &object)?
                .ok_or_else(|| anyhow::anyhow!("copy consumer disabled"))?;
            let domain = if matches!(message.operation, Operation::SourceRead { .. }) {
                config.source_domain(&object, &message.original)?
            } else {
                config.domain(&object, &message.original)?
            };
            if !matches!(message.operation, Operation::SourceRead { .. }) {
                config.validate_pair(&object, &message.original)?;
            }
            ensure!(
                domain.scope(
                    &object,
                    &message.original,
                    !matches!(message.operation, Operation::SourceRead { .. })
                )? == message.scope,
                "copy destination physical scope differs"
            );
            let name = message.scope.guard_name()?;
            ensure!(
                request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str())
                    && self
                        .env
                        .durable_object(BINDING)?
                        .id_from_name(&name)?
                        .to_string()
                        == self.state.id().to_string(),
                "copy addressed to another guard"
            );

            let _gate = self.gate.lock().await;
            let value = self.copy_handle(&message, &object, domain).await?;
            let (body, signature) = protocol::sign_reply(&guard_key, &message, value)?;
            let headers = worker::Headers::new();
            headers.set(GUARD_HEADER, &signature)?;
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            Ok::<_, anyhow::Error>(Response::from_bytes(body)?.with_headers(headers))
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(_) => Response::error("external copy turn refused", 409),
        }
    }

    /// Reads an exact retained original without issuing another provider effect.
    ///
    /// # Errors
    /// Refuses an unauthenticated selector, wrong physical address or changed SQL pins.
    pub(crate) async fn copy_original_fetch(
        &self,
        request: &mut HttpRequest,
    ) -> worker::Result<Response> {
        let result = async {
            ensure!(
                request.method() == Method::Post,
                "copy lookup requires POST"
            );
            let body = crate::hybrid::read_bounded_body(request, MAX_MESSAGE)
                .await?
                .ok_or_else(|| anyhow::anyhow!("copy lookup oversized"))?;
            let signature = request
                .headers()
                .get(GUARD_HEADER)?
                .ok_or_else(|| anyhow::anyhow!("copy lookup authentication absent"))?;
            let guard_key = key(&self.env)?;
            let message = super::discovery::authenticate(&guard_key, &signature, &body)?;
            let object = configured(&self.env)?
                .ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
            let config = config::configured(&self.env, &object)?
                .ok_or_else(|| anyhow::anyhow!("copy consumer disabled"))?;
            let domain = config
                .domains
                .iter()
                .find(|domain| {
                    domain
                        .commitment()
                        .is_ok_and(|digest| digest == message.selector.profile_digest)
                })
                .ok_or_else(|| anyhow::anyhow!("copy lookup profile absent"))?;
            ensure!(
                domain.selector_scope(&object, &message.selector)? == message.scope,
                "copy lookup physical scope differs"
            );
            let name = message.scope.guard_name()?;
            ensure!(
                request.headers().get(SCOPE_HEADER)?.as_deref() == Some(name.as_str())
                    && self
                        .env
                        .durable_object(BINDING)?
                        .id_from_name(&name)?
                        .to_string()
                        == self.state.id().to_string(),
                "copy lookup addressed to another guard"
            );

            let _gate = self.gate.lock().await;
            let storage = self.state.storage();
            let raw = storage
                .get::<String>(&session_key(&message.selector.copy_id()?))
                .await?;
            let session: Option<CopySession> = decode(raw, MAX_MESSAGE)?;
            let retained = match session {
                Some(session) => {
                    session.validate(session.original())?;
                    let progress = session.progress()?;
                    message
                        .selector
                        .validate_retained(session.original(), &progress)?;
                    domain.validate_original(&object, session.original())?;
                    let head = load_head(&storage).await?;
                    require_current_closed(&storage, head.as_ref(), &object, &session).await?;
                    Some(super::discovery::Retained {
                        original: session.original().clone(),
                        progress,
                    })
                }
                None => None,
            };
            let (body, signature) = super::discovery::sign_reply(&guard_key, &message, retained)?;
            let headers = worker::Headers::new();
            headers.set(GUARD_HEADER, &signature)?;
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            Ok::<_, anyhow::Error>(Response::from_bytes(body)?.with_headers(headers))
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(_) => Response::error("external copy original lookup refused", 409),
        }
    }

    async fn copy_handle(
        &self,
        message: &Request,
        object: &ObjectConfig,
        domain: &config::Domain,
    ) -> Result<Reply> {
        let storage = self.state.storage();
        let prior = load_head(&storage).await?;
        if let Some(head) = &prior {
            head.validate(object, &message.scope)?;
        }
        if let Operation::SourceRead { read_lease } = &message.operation {
            ensure!(
                message.original.source_incarnation()? == aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::ProviderVersion,
                "protected source requires a held range guard"
            );
            crate::direct_guard::deny_legacy(&storage).await?;
            let mut head = match &prior {
                Some(head) => head.clone(),
                None => initialize(object, domain, message)?,
            };
            // The source version is immutable; this advances only the real
            // source-key read floor. It cannot reserve or settle a destination
            // turn, and active physical workflows remain excluded.
            ensure!(
                head.pending.is_none()
                    && head.observation.is_none()
                    && head.stage.is_none()
                    && head.copy.is_none()
                    && head.oci.is_none()
                    && head.mirror.is_none(),
                "source key has another active physical workflow"
            );
            ensure!(
                object.clock().observed_at < message.permission_expires_at.get(),
                "copy source application cutoff expired"
            );
            head.floor = object
                .verifier()?
                .validate_lease(
                    read_lease.as_bytes(),
                    &domain.read_cohort,
                    &object.timing_profile,
                    &head.floor,
                    &head.scope.full_key,
                    LeaseEffect::Read,
                    object.clock(),
                )?
                .next_floor;
            let next = serde_json::to_string(&head)?;
            storage
                .transaction(move |transaction| {
                    let prior = prior.clone();
                    let next = next.clone();
                    async move {
                        let current: Option<Head> =
                            decode(transaction_string(&transaction, HEAD).await?, MAX_MESSAGE)
                                .map_err(error)?;
                        if current != prior {
                            return Err(error("copy source floor CAS refused"));
                        }
                        transaction.put(HEAD, next).await
                    }
                })
                .await?;
            return Ok(Reply::ReadAuthorized { floor: head.floor });
        }
        let stored = load_session(&storage, &message.original).await?;
        match &message.operation {
            Operation::SourceRead { .. } => anyhow::bail!("source read was not handled"),
            Operation::Lookup => match stored {
                Some(session) => {
                    require_current_closed(&storage, prior.as_ref(), object, &session).await?;
                    Ok(Reply::Progress {
                        progress: session.progress()?,
                    })
                }
                None => Ok(Reply::Unseen),
            },
            Operation::Begin {
                control,
                write_lease,
            } => {
                crate::direct_guard::deny_legacy(&storage).await?;
                let mut session = match &stored {
                    Some(session) => session.clone(),
                    None => CopySession::initialize(message.original.clone())?,
                };
                // Terminal replay precedes renewal and never grants another effect.
                if matches!(session.phase(), CopyPhase::Closed | CopyPhase::Aborted)
                    || session.pending().is_some()
                {
                    require_current_closed(&storage, prior.as_ref(), object, &session).await?;
                    return Ok(Reply::Progress {
                        progress: session.progress()?,
                    });
                }
                ensure!(
                    object.clock().observed_at < message.permission_expires_at.get(),
                    "copy application dispatch cutoff expired"
                );
                let action = match control {
                    CopyControl::Advance => session.next_action()?,
                    CopyControl::Abort => session.abort_action()?,
                    CopyControl::Status => anyhow::bail!("status cannot dispatch"),
                };
                let mut head = match &prior {
                    Some(head) => head.clone(),
                    None => initialize(object, domain, message)?,
                };
                ensure!(
                    head.pending.is_none()
                        && head.observation.is_none()
                        && head.stage.is_none()
                        && head.oci.is_none()
                        && head.mirror.is_none()
                        && head.receipts.get() < MAX_RECEIPTS,
                    "another physical workflow or receipt bound blocks copy"
                );
                if let Some(owner) = &head.copy {
                    owner.matches(&message.original)?;
                } else {
                    ensure!(
                        stored.is_none(),
                        "active copy session lost its physical owner"
                    );
                    let effects = if message.original.source_object.bytes.get() == 0 {
                        1
                    } else {
                        i64::from(message.original.part_count()?) + 2
                    };
                    ensure!(
                        head.receipts
                            .get()
                            .checked_add(effects)
                            .is_some_and(|count| count <= MAX_RECEIPTS)
                            && head.incarnation.get() < super::super::stage::state::MAX_INCARNATION,
                        "copy cannot reserve complete receipt/incarnation capacity"
                    );
                }
                let validated = object.verifier()?.validate_lease(
                    write_lease.as_bytes(),
                    &domain.write_cohort,
                    &object.timing_profile,
                    &head.floor,
                    &head.scope.full_key,
                    effect(&action),
                    object.clock(),
                )?;
                head.floor = validated.next_floor;
                let mut nonce = [0_u8; 32];
                rand::rngs::OsRng
                    .try_fill_bytes(&mut nonce)
                    .map_err(|_| anyhow::anyhow!("copy dispatch randomness unavailable"))?;
                let turn = session.begin(&message.original, action, hex::encode(nonce))?;
                head.copy = Some(Owner::new(&message.original, domain.commitment()?)?);
                let source_state = if matches!(turn.action, CopyAction::Part { .. }) {
                    Some(session.source_continuation_for(&turn)?)
                } else {
                    None
                };
                commit(
                    &storage,
                    prior,
                    head.clone(),
                    &message.original,
                    stored,
                    &session,
                    BTreeMap::new(),
                )
                .await?;
                let destination_stamp = if message.original.destination_incarnation()? == aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::GuardedClosure {
                    Some(aos_hub_core::storage_authority::StorageGuardStamp {
                        physical_authority_id: message.scope.physical_authority_id.clone(),
                        incarnation: aos_hub_core::storage_authority::GuardIncarnation::parse(
                            head.incarnation
                                .get()
                                .checked_add(1)
                                .ok_or_else(|| anyhow::anyhow!("copy incarnation exhausted"))?
                                .to_string(),
                        )?,
                    })
                } else {
                    None
                };
                Ok(Reply::Dispatch {
                    destination_stamp,
                    turn,
                    floor: head.floor,
                    source_state,
                })
            }
            Operation::Terminal { receipt } => {
                let mut session = stored
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("copy terminal without retained session"))?;
                let receipt_key = receipt_key(&receipt.turn.action_id);
                if let Some(retained) = load_receipt(&storage, &receipt.turn.action_id).await? {
                    ensure!(retained == *receipt, "copy positive receipt changed");
                    require_current_closed(&storage, prior.as_ref(), object, &session).await?;
                    return Ok(Reply::Progress {
                        progress: session.progress()?,
                    });
                }
                let mut head = prior
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("copy terminal without physical owner"))?;
                head.copy
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("copy physical owner absent"))?
                    .matches(&message.original)?;
                if message.original.destination_incarnation()? == aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::GuardedClosure {
                    if let CopyOutcome::Closed { destination, .. } = &receipt.outcome {
                        let stamp = destination
                            .guard_stamp
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("protected Complete stamp absent"))?;
                        ensure!(
                            stamp.physical_authority_id == message.scope.physical_authority_id
                                && stamp.incarnation.as_str()
                                    == head
                                        .incarnation
                                        .get()
                                        .checked_add(1)
                                        .ok_or_else(|| anyhow::anyhow!(
                                            "copy incarnation exhausted"
                                        ))?
                                        .to_string(),
                            "protected Complete has another physical incarnation"
                        );
                    }
                }
                session.acknowledge(receipt)?;
                head.receipts = LeaseInteger::new(
                    head.receipts
                        .get()
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("copy receipt count overflow"))?,
                )?;
                ensure!(
                    head.receipts.get() <= MAX_RECEIPTS,
                    "copy receipt bound exhausted"
                );
                let encoded = serde_json::to_string(receipt)?;
                ensure!(encoded.len() <= MAX_MESSAGE, "copy receipt oversized");
                let mut records = BTreeMap::new();
                records.insert(receipt_key, encoded.clone());
                if let CopyAction::Part { number, .. } = &receipt.turn.action {
                    records.insert(part_key(&message.original.copy_id()?, *number), encoded);
                }
                if session.phase() == CopyPhase::Closed {
                    head.incarnation = WireInteger::new(
                        head.incarnation
                            .get()
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("copy incarnation exhausted"))?,
                    );
                    // Existing visible receipts describe the earlier incarnation.
                    // The new copy has its own actual versioned positive receipt.
                    head.visible_receipt = if message.original.destination_incarnation()? == aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::GuardedClosure {
                        Some(super::super::state::VisibleReceipt {
                            kind: super::super::state::VisibleKind::CopyDestination,
                            operation_id: receipt.turn.action_id.clone(),
                            receipt_digest: digest(receipt)?,
                            context_digest: message.original.fingerprint()?,
                            incarnation: head.incarnation,
                            stage_configuration: Some(message.original.profile_digest.clone()),
                        })
                    } else {
                        None
                    };
                }
                if matches!(session.phase(), CopyPhase::Closed | CopyPhase::Aborted) {
                    head.copy = None;
                }
                head.validate(object, &message.scope)?;
                commit(
                    &storage,
                    prior,
                    head,
                    &message.original,
                    stored,
                    &session,
                    records,
                )
                .await?;
                Ok(Reply::Progress {
                    progress: session.progress()?,
                })
            }
            Operation::ManifestPage {
                turn,
                first_part,
                limit,
            } => {
                let session =
                    stored.ok_or_else(|| anyhow::anyhow!("copy manifest owner absent"))?;
                ensure!(
                    session.pending() == Some(turn),
                    "copy manifest turn differs"
                );
                let CopyAction::Complete { upload_id, .. } = &turn.action else {
                    anyhow::bail!("copy manifest requires retained Complete");
                };
                let count = message.original.part_count()?;
                ensure!(
                    *first_part <= count,
                    "copy manifest starts outside actual parts"
                );
                let end = first_part.saturating_add(*limit - 1).min(count);
                let mut parts = Vec::with_capacity((end - first_part + 1) as usize);
                for number in *first_part..=end {
                    let raw = storage
                        .get::<String>(&part_key(&message.original.copy_id()?, number))
                        .await?;
                    let receipt: CopyReceipt = decode(raw, MAX_MESSAGE)?
                        .ok_or_else(|| anyhow::anyhow!("copy positive part receipt absent"))?;
                    ensure!(
                        receipt.turn.copy_id == turn.copy_id
                            && receipt.turn.original_digest == turn.original_digest,
                        "copy manifest part original differs"
                    );
                    let (offset, bytes) = message.original.part_range(number)?;
                    let CopyAction::Part {
                        upload_id: observed,
                        number: observed_number,
                        offset: observed_offset,
                        bytes: observed_bytes,
                        ..
                    } = &receipt.turn.action
                    else {
                        anyhow::bail!("copy manifest record is not a part");
                    };
                    ensure!(
                        observed == upload_id
                            && *observed_number == number
                            && *observed_offset == offset
                            && *observed_bytes == bytes,
                        "copy manifest part geometry differs"
                    );
                    let CopyOutcome::Part { etag, sha256, .. } = receipt.outcome else {
                        anyhow::bail!("copy manifest lacks positive part acknowledgement");
                    };
                    parts.push(protocol::Part {
                        number,
                        etag,
                        sha256,
                        bytes,
                    });
                }
                Ok(Reply::ManifestPage {
                    parts,
                    next_part: (end < count).then_some(end + 1),
                })
            }
        }
    }
}

fn effect(action: &CopyAction) -> LeaseEffect {
    match action {
        CopyAction::Create => LeaseEffect::MultipartCreate,
        CopyAction::EmptyPut => LeaseEffect::Put,
        CopyAction::Part { .. } => LeaseEffect::MultipartPart,
        CopyAction::Complete { .. } => LeaseEffect::MultipartComplete,
        CopyAction::Abort { .. } => LeaseEffect::MultipartAbort,
    }
}

fn initialize(object: &ObjectConfig, domain: &config::Domain, message: &Request) -> Result<Head> {
    let floor = EpochLeaseFloor::initialize_fresh_guard(
        domain.write_cohort.authority.clone(),
        object.executor_identity.clone(),
        message.scope.full_key.clone(),
        &object.timing_profile,
        object.clock(),
    )?;
    Ok(Head {
        version: 1,
        scope: message.scope.clone(),
        configuration: digest(object)?,
        floor,
        pending: None,
        observation: None,
        visible_receipt: None,
        receipts: LeaseInteger::new(0)?,
        incarnation: WireInteger::new(0),
        stage: None,
        copy: None,
        oci: None,
        mirror: None,
    })
}

fn session_key(copy_id: &str) -> String {
    format!("external-copy/session/v1/{copy_id}")
}

fn receipt_key(action_id: &str) -> String {
    format!("external-copy/receipt/v1/{action_id}")
}

fn part_key(copy_id: &str, number: u32) -> String {
    format!("external-copy/part/v1/{copy_id}/{number}")
}

async fn load_session(
    storage: &Storage,
    original: &ExternalCopyOriginal,
) -> Result<Option<CopySession>> {
    let raw = storage
        .get::<String>(&session_key(&original.copy_id()?))
        .await?;
    let value: Option<CopySession> = decode(raw, MAX_MESSAGE)?;
    if let Some(session) = &value {
        session.validate(original)?;
    }
    Ok(value)
}

async fn load_receipt(storage: &Storage, action_id: &str) -> Result<Option<CopyReceipt>> {
    decode(
        storage.get::<String>(&receipt_key(action_id)).await?,
        MAX_MESSAGE,
    )
}

async fn commit(
    storage: &Storage,
    expected_head: Option<Head>,
    next_head: Head,
    original: &ExternalCopyOriginal,
    expected_session: Option<CopySession>,
    next_session: &CopySession,
    records: BTreeMap<String, String>,
) -> Result<()> {
    ensure!(records.len() <= 2, "copy transaction record bound exceeded");
    let session_key = session_key(&original.copy_id()?);
    let next_session = serde_json::to_string(next_session)?;
    let next_head = serde_json::to_string(&next_head)?;
    ensure!(
        next_session.len() <= MAX_MESSAGE && next_head.len() <= MAX_MESSAGE,
        "copy retained state oversized"
    );
    storage
        .transaction(move |transaction| {
            let expected_head = expected_head.clone();
            let expected_session = expected_session.clone();
            let session_key = session_key.clone();
            let next_session = next_session.clone();
            let next_head = next_head.clone();
            let records = records.clone();
            async move {
                let head: Option<Head> =
                    decode(transaction_string(&transaction, HEAD).await?, MAX_MESSAGE)
                        .map_err(error)?;
                let session: Option<CopySession> = decode(
                    transaction_string(&transaction, &session_key).await?,
                    MAX_MESSAGE,
                )
                .map_err(error)?;
                if head != expected_head || session != expected_session {
                    return Err(error("copy original/head CAS refused"));
                }
                for name in records.keys() {
                    if transaction_string(&transaction, name).await?.is_some() {
                        return Err(error("copy immutable receipt already exists"));
                    }
                }
                for (name, value) in records {
                    transaction.put(&name, value).await?;
                }
                transaction.put(&session_key, next_session).await?;
                transaction.put(HEAD, next_head).await?;
                Ok(())
            }
        })
        .await?;
    Ok(())
}

/// Reads the exact current positive Copy closure without issuing another turn.
///
/// # Errors
/// Refuses unknown ownership, replacement, missing original or altered receipt.
pub(super) async fn closed_copy_source(
    storage: &Storage,
    head: &Head,
    object: &ObjectConfig,
) -> Result<aos_hub_core::storage_authority::external_object::copy::source::CopySourceClosure> {
    use super::super::state::VisibleKind;
    head.validate(object, &head.scope)?;
    head.require_cleanup_ready()?;
    ensure!(head.stage.is_none(), "copy source has active staging");
    let visible = head
        .visible_receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("copy source has no visible closure"))?;
    ensure!(
        visible.kind == VisibleKind::CopyDestination,
        "copy source belongs to another producer"
    );
    let receipt = load_receipt(storage, &visible.operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("copy closure receipt absent"))?;
    ensure!(
        receipt.turn.action_id == visible.operation_id
            && receipt.turn.original_digest == visible.context_digest
            && digest(&receipt)? == visible.receipt_digest,
        "copy closure receipt changed"
    );
    let session: CopySession = decode(
        storage
            .get::<String>(&session_key(&receipt.turn.copy_id))
            .await?,
        MAX_MESSAGE,
    )?
    .ok_or_else(|| anyhow::anyhow!("copy closure original absent"))?;
    session.validate(session.original())?;
    let progress = session.progress()?;
    let CopyOutcome::Closed {
        destination,
        sha256,
    } = &receipt.outcome
    else {
        anyhow::bail!("copy closure is not positive");
    };
    ensure!(
        session.original().destination_incarnation()? == aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::GuardedClosure
            && session.original().fingerprint()? == visible.context_digest
            && visible.stage_configuration.as_ref() == Some(&session.original().profile_digest)
            && progress.phase == CopyPhase::Closed
            && progress.destination.as_ref() == Some(destination)
            && progress.sha256.as_ref() == Some(sha256),
        "copy closure original or final state differs"
    );
    let stamp = destination
        .guard_stamp
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("copy closure guard stamp absent"))?;
    ensure!(
        stamp.physical_authority_id == head.scope.physical_authority_id
            && stamp.incarnation.as_str() == head.incarnation.get().to_string(),
        "copy closure incarnation is no longer current"
    );
    let closure =
        aos_hub_core::storage_authority::external_object::copy::source::CopySourceClosure {
            guard_stamp: stamp.clone(),
            receipt_digest: visible.receipt_digest.clone(),
            sha256: sha256.clone(),
            bytes: destination.bytes,
            etag: Some(destination.etag.clone()),
        };
    closure.validate()?;
    Ok(closure)
}

async fn require_current_closed(
    storage: &Storage,
    head: Option<&Head>,
    object: &ObjectConfig,
    session: &CopySession,
) -> Result<()> {
    if session.original().destination_incarnation()? == aos_hub_core::storage_authority::external_object::copy::CopyIncarnationMode::GuardedClosure && session.phase() == CopyPhase::Closed {
        let head =
            head.ok_or_else(|| anyhow::anyhow!("protected copy lost current physical head"))?;
        let closure = closed_copy_source(storage, head, object).await?;
        let progress = session.progress()?;
        ensure!(
            progress
                .destination
                .as_ref()
                .and_then(|destination| destination.guard_stamp.as_ref())
                == Some(&closure.guard_stamp)
                && progress.sha256.as_ref() == Some(&closure.sha256),
            "protected copy positive is no longer the current destination"
        );
    }
    Ok(())
}
