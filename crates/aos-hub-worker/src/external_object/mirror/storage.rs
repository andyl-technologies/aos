//! Atomic External mirror ownership, effect intent and positive receipt records.
//!
//! Every transition compares the exact prior head and full session in one SQLite
//! KV transaction. Pending is retained before SDK dispatch, and errors or expiry
//! never clear it. Positive private stages remain after Native commit as explicit
//! residual cleanup cost; this module dispatches no Delete.
//!
//! ```text
//! external-mirror/session/v1/<original SHA> -> full immutable session
//! external-mirror/receipt/v1/<original SHA>/<effect SHA> -> positive receipt
//! ```

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    direct_upload::WireInteger,
    mirror_work::{
        MirrorOriginal, MirrorProgress, MirrorVerifiedObject, digest,
        external::{
            MirrorExternalClosure,
            journal::{
                MirrorExternalAcceptance, MirrorExternalEffect, MirrorExternalReceipt,
                MirrorExternalSession,
            },
        },
    },
    storage_authority::{
        GuardIncarnation, StorageGuardStamp,
        control::StorageAuthorityObjectScope,
        external_object::copy::source::CopySourceClosure,
        lease::{EpochLeaseFloor, LeaseInteger},
    },
};
use worker::Storage;

use super::super::{
    config::Config as ObjectConfig,
    state::{Head, VisibleKind, VisibleReceipt},
    storage::{HEAD, decode, error, load_head, transaction_string},
};
use super::{config::Domain, state::Owner};

const MAX_SESSION: usize = 256 * 1024;
const MAX_RECEIPT: usize = 16 * 1024;

pub(super) struct Journal {
    storage: Storage,
    pub head: Head,
    pub session: MirrorExternalSession,
}

impl Journal {
    /// Resumes metadata-only acknowledgement beneath the caller's held gate.
    pub(super) fn resume(storage: Storage, head: Head, session: MirrorExternalSession) -> Self {
        Self {
            storage,
            head,
            session,
        }
    }

    pub(super) async fn lookup(
        storage: &Storage,
        original: &MirrorOriginal,
    ) -> Result<Option<MirrorExternalSession>> {
        let session: Option<MirrorExternalSession> = decode(
            storage
                .get::<String>(&session_key(&digest(original)?))
                .await?,
            MAX_SESSION,
        )?;
        if let Some(session) = &session {
            session.validate()?;
            ensure!(
                session.original == *original,
                "mirror retained original changed"
            );
        }
        Ok(session)
    }

    pub(super) async fn open(
        storage: Storage,
        object: &ObjectConfig,
        domain: &Domain,
        original: &MirrorOriginal,
        destination: bool,
        acceptance: MirrorExternalAcceptance,
        source: Option<MirrorProgress>,
    ) -> Result<Self> {
        domain.validate_original(object, original)?;
        let full_key = if destination {
            original.destination_key()
        } else {
            original.stage_key()
        };
        let scope = object.scope(&domain.profile.profile.write_cohort, full_key)?;
        let prior_head = load_head(&storage).await?;
        let head = match &prior_head {
            Some(head) => {
                head.validate(object, &scope)?;
                head.clone()
            }
            None => Head::initialize_floor(
                object,
                &scope,
                &domain.profile.profile.write_cohort,
                object.clock(),
            )?,
        };
        ensure!(
            head.pending.is_none()
                && head.observation.is_none()
                && head.stage.is_none()
                && head.copy.is_none()
                && head.oci.is_none(),
            "another physical workflow owns the mirror key"
        );
        let prior_session = Self::lookup(&storage, original).await?;
        let session = if let Some(session) = &prior_session {
            ensure!(
                session.destination == destination
                    && session.configuration == domain.commitment()?,
                "mirror retained physical role or installed domain changed"
            );
            // A fresh loader may only shorten availability. It cannot replace
            // the first accepted artifact/window retained before any effect.
            ensure!(
                session.acceptance == acceptance,
                "mirror original acceptance changed"
            );
            session.clone()
        } else {
            ensure!(
                head.mirror.is_none() && (destination || head.visible_receipt.is_none()),
                "mirror private key already has an original incarnation"
            );
            MirrorExternalSession::declare(
                original.clone(),
                destination,
                domain.commitment()?,
                acceptance,
                source,
            )?
        };
        let owner = owner(&session)?;
        let mut next_head = head;
        if session.acknowledged_commit.is_none() {
            ensure!(
                next_head
                    .mirror
                    .as_ref()
                    .is_none_or(|current| current == &owner),
                "mirror physical key has another unresolved original"
            );
            next_head.mirror = Some(owner);
        } else {
            ensure!(
                next_head
                    .mirror
                    .as_ref()
                    .is_none_or(|current| current == &owner),
                "archived mirror replay cannot replace a later owner"
            );
        }
        next_head.validate(object, &scope)?;
        commit(
            &storage,
            prior_head,
            prior_session,
            next_head.clone(),
            session.clone(),
            BTreeMap::new(),
        )
        .await?;
        Ok(Self {
            storage,
            head: next_head,
            session,
        })
    }

    /// Retains the first actual upstream incarnation before writing its bytes.
    pub(super) async fn retain_upstream_etag(&mut self, etag: Option<String>) -> Result<()> {
        ensure!(
            !self.session.destination
                && self.session.pending.is_none()
                && self.session.closed.is_none(),
            "mirror upstream observation changed physical phase"
        );
        if let Some(tag) = &etag {
            aos_hub_core::surface_write::strong_if_match_etag(tag)?;
        }
        ensure!(
            self.session
                .progress
                .upstream_etag
                .as_ref()
                .is_none_or(|prior| etag.as_ref() == Some(prior)),
            "mirror upstream incarnation changed its first observation"
        );
        let mut next = self.session.clone();
        next.progress.upstream_etag = etag;
        self.retain(self.head.clone(), next, BTreeMap::new()).await
    }

    /// Atomically retains the actual validated lease floor and first effect.
    pub(super) async fn begin(
        &mut self,
        effect: MirrorExternalEffect,
        nonce: String,
        floor: EpochLeaseFloor,
    ) -> Result<()> {
        ensure!(
            self.head.mirror.as_ref() == Some(&owner(&self.session)?),
            "mirror dispatch lost the permanent owner"
        );
        let next = self.session.begin(effect, nonce)?;
        let mut head = self.head.clone();
        head.floor = floor;
        self.retain(head, next, BTreeMap::new()).await
    }

    pub(super) fn next_stamp(&self) -> Result<StorageGuardStamp> {
        ensure!(
            self.head.mirror.as_ref() == Some(&owner(&self.session)?),
            "mirror completion lost physical ownership"
        );
        let incarnation = self
            .head
            .incarnation
            .get()
            .checked_add(1)
            .context("mirror guard incarnation exhausted")?;
        ensure!(
            incarnation <= super::super::stage::state::MAX_INCARNATION,
            "mirror guard incarnation exhausted"
        );
        Ok(StorageGuardStamp {
            physical_authority_id: self.head.scope.physical_authority_id.clone(),
            incarnation: GuardIncarnation::parse(incarnation.to_string())?,
        })
    }

    pub(super) async fn acknowledge(&mut self, receipt: MirrorExternalReceipt) -> Result<()> {
        let next = self.session.acknowledge(&receipt)?;
        let original_digest = digest(&next.original)?;
        let mut records = BTreeMap::new();
        records.insert(
            receipt_key(&original_digest, &receipt.pending.effect_digest),
            serde_json::to_string(&receipt)?,
        );
        let mut head = self.head.clone();
        ensure!(
            head.mirror.as_ref() == Some(&owner(&next)?),
            "mirror receipt changed physical owner"
        );
        if let Some(closed) = &next.closed {
            records.insert(
                completion_key(&original_digest, next.destination),
                serde_json::to_string(&receipt.pending.effect_digest)?,
            );
            ensure!(
                closed.guard_stamp == self.next_stamp()?,
                "mirror completion changed the permanent incarnation"
            );
            head.incarnation = WireInteger::new(head.incarnation.get() + 1);
            head.visible_receipt = Some(VisibleReceipt {
                kind: if next.destination {
                    VisibleKind::MirrorDestination
                } else {
                    VisibleKind::MirrorStage
                },
                operation_id: original_digest.clone(),
                context_digest: original_digest,
                receipt_digest: closed.receipt_digest.clone(),
                incarnation: head.incarnation,
                stage_configuration: Some(next.configuration.clone()),
            });
        }
        // Completion alone is insufficient: verification and exact SQL commit
        // acknowledgement must occur before any independent source reader.
        self.retain(head, next, records).await
    }

    pub(super) async fn verified(&mut self, verified: MirrorVerifiedObject) -> Result<()> {
        let next = self.session.verified(verified)?;
        self.retain(self.head.clone(), next, BTreeMap::new()).await
    }

    /// Archives only independently checked exact final progress and SQL ACK.
    pub(super) async fn acknowledge_commit(
        &mut self,
        progress: &MirrorProgress,
        commit_digest: &str,
    ) -> Result<()> {
        let next = self.session.acknowledge_commit(progress, commit_digest)?;
        let mut head = self.head.clone();
        let expected_owner = owner(&next)?;
        ensure!(
            head.mirror
                .as_ref()
                .is_none_or(|owner| owner == &expected_owner),
            "mirror ACK replaced another physical owner"
        );
        head.mirror = None;
        self.retain(head, next, BTreeMap::new()).await
    }

    pub(super) async fn retain_read_floor(&mut self, floor: EpochLeaseFloor) -> Result<()> {
        ensure!(
            self.session.pending.is_none() && self.session.closed.is_some(),
            "mirror read is not an exact positive completion"
        );
        let mut head = self.head.clone();
        head.floor = floor;
        self.retain(head, self.session.clone(), BTreeMap::new())
            .await
    }

    async fn retain(
        &mut self,
        head: Head,
        session: MirrorExternalSession,
        records: BTreeMap<String, String>,
    ) -> Result<()> {
        session.validate()?;
        commit(
            &self.storage,
            Some(self.head.clone()),
            Some(self.session.clone()),
            head.clone(),
            session.clone(),
            records,
        )
        .await?;
        self.head = head;
        self.session = session;
        Ok(())
    }
}

/// Loads actual completed evidence under the already held exact physical gate.
pub(super) async fn current(
    storage: &Storage,
    object: &ObjectConfig,
    original: &MirrorOriginal,
    destination: bool,
) -> Result<(Head, MirrorExternalSession)> {
    let session = Journal::lookup(storage, original)
        .await?
        .context("mirror positive original absent")?;
    let closed = session
        .closed
        .as_ref()
        .context("mirror positive completion absent")?;
    let head = load_head(storage)
        .await?
        .context("mirror physical head absent")?;
    head.validate(object, &closed.scope)?;
    let expected_owner = owner(&session)?;
    ensure!(
        session.destination == destination
            && session.pending.is_none()
            && head.pending.is_none()
            && head.observation.is_none()
            && head.stage.is_none()
            && head.copy.is_none()
            && head.oci.is_none()
            && head
                .mirror
                .as_ref()
                .is_none_or(|owner| owner == &expected_owner),
        "mirror closure is pending or belongs to another owner"
    );
    ensure!(
        if session.acknowledged_commit.is_some() {
            head.mirror.is_none()
        } else {
            head.mirror.as_ref() == Some(&expected_owner)
        },
        "mirror completion lost its exact retained ownership state"
    );
    let visible = head
        .visible_receipt
        .as_ref()
        .context("mirror visible receipt absent")?;
    ensure!(
        visible.kind
            == (if destination {
                VisibleKind::MirrorDestination
            } else {
                VisibleKind::MirrorStage
            })
            && visible.context_digest == digest(original)?
            && visible.receipt_digest == closed.receipt_digest
            && visible.stage_configuration.as_ref() == Some(&session.configuration)
            && closed.guard_stamp.incarnation.as_str() == head.incarnation.get().to_string(),
        "mirror positive visible incarnation changed"
    );
    let receipt: MirrorExternalReceipt = decode(
        storage
            .get::<String>(&receipt_key(
                &digest(original)?,
                &visible_receipt_effect(storage, original, destination).await?,
            ))
            .await?,
        MAX_RECEIPT,
    )?
    .context("mirror positive receipt absent")?;
    ensure!(
        digest(&receipt)? == closed.receipt_digest
            && receipt.original_digest == digest(original)?
            && matches!(&receipt.positive,
            aos_hub_core::mirror_work::external::journal::MirrorExternalPositive::Completed { object, guard_stamp }
                if *object == closed.object && *guard_stamp == closed.guard_stamp),
        "mirror closure lost its immutable positive receipt"
    );
    Ok((head, session))
}

// The completed pending effect is retained separately by its original-bound
// locator; no provider HEAD or guessed upload receipt can reconstruct it.
async fn visible_receipt_effect(
    storage: &Storage,
    original: &MirrorOriginal,
    destination: bool,
) -> Result<String> {
    let key = completion_key(&digest(original)?, destination);
    decode(storage.get::<String>(&key).await?, 1024)?
        .context("mirror completion receipt locator absent")
}

pub(in crate::external_object) async fn closed_source(
    storage: &Storage,
    object: &ObjectConfig,
    head: &Head,
) -> Result<CopySourceClosure> {
    ensure!(
        head.mirror.is_none(),
        "mirror source remains unacknowledged"
    );
    let visible = head
        .visible_receipt
        .as_ref()
        .context("mirror source receipt absent")?;
    let session: MirrorExternalSession = decode(
        storage
            .get::<String>(&session_key(&visible.context_digest))
            .await?,
        MAX_SESSION,
    )?
    .context("mirror source lost retained original")?;
    let (current_head, checked) =
        current(storage, object, &session.original, session.destination).await?;
    ensure!(
        current_head == *head && checked == session && session.acknowledged_commit.is_some(),
        "mirror source changed or lacks exact Native acknowledgement"
    );
    let verified = if session.destination {
        session.progress.destination.as_ref()
    } else {
        session.progress.verified.as_ref()
    }
    .context("mirror source lacks full content verification")?;
    let closed = session
        .closed
        .as_ref()
        .context("mirror source completion absent")?;
    let closure = CopySourceClosure {
        guard_stamp: closed.guard_stamp.clone(),
        receipt_digest: closed.receipt_digest.clone(),
        sha256: verified.sha256.clone(),
        bytes: LeaseInteger::new(i64::try_from(verified.object.size)?)?,
        etag: Some(verified.object.etag.clone()),
    };
    closure.validate()?;
    Ok(closure)
}

async fn commit(
    storage: &Storage,
    expected_head: Option<Head>,
    expected_session: Option<MirrorExternalSession>,
    head: Head,
    session: MirrorExternalSession,
    records: BTreeMap<String, String>,
) -> Result<()> {
    session.validate()?;
    let key = session_key(&digest(&session.original)?);
    let encoded = serde_json::to_string(&session)?;
    ensure!(
        encoded.len() <= MAX_SESSION && records.values().all(|value| value.len() <= MAX_RECEIPT),
        "mirror journal exceeds compact cell bounds"
    );
    storage
        .transaction(move |transaction| {
            let expected_head = expected_head.clone();
            let expected_session = expected_session.clone();
            let head = head.clone();
            let key = key.clone();
            let encoded = encoded.clone();
            let records = records.clone();
            async move {
                let current_head: Option<Head> = decode(
                    transaction_string(&transaction, HEAD).await?,
                    super::super::protocol::MAX_MESSAGE,
                )
                .map_err(error)?;
                let current_session: Option<MirrorExternalSession> =
                    decode(transaction_string(&transaction, &key).await?, MAX_SESSION)
                        .map_err(error)?;
                if current_head != expected_head || current_session != expected_session {
                    return Err(error("mirror original/head CAS refused"));
                }
                for (key, value) in &records {
                    if transaction_string(&transaction, key)
                        .await?
                        .is_some_and(|prior| prior != *value)
                    {
                        return Err(error("mirror immutable provider receipt changed"));
                    }
                }
                for (key, value) in records {
                    transaction.put(&key, value).await?;
                }
                transaction.put(&key, encoded).await?;
                transaction
                    .put(HEAD, serde_json::to_string(&head).map_err(error)?)
                    .await?;
                Ok(())
            }
        })
        .await?;
    Ok(())
}

fn session_key(original: &str) -> String {
    format!("external-mirror/session/v1/{original}")
}

fn receipt_key(original: &str, effect: &str) -> String {
    format!("external-mirror/receipt/v1/{original}/{effect}")
}

fn completion_key(original: &str, destination: bool) -> String {
    format!("external-mirror/completion/v1/{original}/{destination}")
}

/// Constructs a compact pointer only from the validated full journal.
fn owner(session: &MirrorExternalSession) -> Result<Owner> {
    session.validate()?;
    let owner = Owner {
        original_digest: digest(&session.original)?,
        configuration: session.configuration.clone(),
        destination: session.destination,
    };
    owner.validate()?;
    Ok(owner)
}
