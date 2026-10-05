//! Atomic OCI originals, ordered source pages and positive effect receipts.
//!
//! All records live in the existing full-key guard's SQLite KV. Exact session,
//! head, receipt and part comparisons precede one atomic update. An unknown
//! effect stays pending permanently; neither expiry nor provider HEAD clears it.
//!
//! ```text
//! external-oci/session/v1/<original SHA> -> full immutable original + progress
//! external-oci/source/v1/<original SHA>/<index> -> immutable source descriptor
//! external-oci/receipt/v1/<original SHA>/<effect SHA> -> exact positive receipt
//! external-oci/part/v1/<original SHA>/<number> -> exact positive part tag
//! ```

use std::collections::BTreeMap;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    direct_upload::WireInteger,
    storage_authority::external_object::oci::{control::ExternalOciRequest, OciSourceOriginal},
    storage_authority::{
        control::StorageAuthorityObjectScope, GuardIncarnation, StorageGuardStamp,
    },
    surface_write::PartTag,
};
use serde::{Deserialize, Serialize};
use worker::{State, Storage};

use super::super::{
    config::Config as ObjectConfig,
    protocol::MAX_MESSAGE,
    state::{Head, VisibleKind, VisibleReceipt},
    storage::{decode, error, load_head, transaction_string, HEAD},
};
use super::{
    config::Config,
    state::{Effect, Phase, Receipt, Session},
};

const MAX_SESSION: usize = 96 * 1024;
const MAX_RECORD: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredPart {
    pub part_number: u32,
    pub bytes: aos_hub_core::storage_authority::external_object::oci::OciBytes,
    pub etag: String,
    pub receipt_digest: String,
}

pub(super) struct Journal {
    storage: Storage,
    pub head: Head,
    pub session: Session,
}

impl Journal {
    /// Loads only the actual still-visible positive original on this full key.
    pub(super) async fn visible(storage: &Storage, object: &ObjectConfig,
        lookup: &aos_hub_core::storage_authority::external_object::oci::source::OciSourceLookup,
    ) -> Result<Session> {
        let head = load_head(storage).await?.context("OCI source has no retained positive head")?;
        head.validate(object, &lookup.scope)?;
        let visible = head.visible_receipt.as_ref().context("OCI source has no visible receipt")?;
        ensure!(matches!(visible.kind, VisibleKind::OciStage | VisibleKind::OciDestination),
            "OCI source belongs to another producer");
        let session: Session = decode(storage.get::<String>(
            &session_key(&visible.context_digest)).await?, MAX_SESSION)?
            .context("OCI source lost its original")?;
        session.validate()?;
        let closed = session.closed.as_ref().context("OCI source is not positively complete")?;
        closed_for_lookup(storage, object, &session.original, closed).await?;
        ensure!(session.original.fingerprint()? == visible.context_digest,
            "OCI source changed its original receipt");
        Ok(session)
    }

    pub(super) async fn recover(
        storage: &Storage,
        proposed: &aos_hub_core::storage_authority::external_object::oci::ExternalOciOriginal,
    ) -> Result<Option<Session>> {
        let selected: Option<String> = decode(storage.get::<String>(
            &selection_key(&proposed.selection_digest()?)).await?, MAX_RECORD)?;
        let Some(digest) = selected else { return Ok(None); };
        ensure!(super::super::protocol::digest_string(&digest),
            "external OCI locator is malformed");
        let retained: Session = decode(storage.get::<String>(&session_key(&digest)).await?, MAX_SESSION)?
            .context("external OCI locator lost its original")?;
        retained.validate()?;
        ensure!(retained.original.fingerprint()? == digest
            && retained.original.selection_digest()? == proposed.selection_digest()?,
            "external OCI locator changed its exact business selection");
        Ok(Some(retained))
    }

    pub(super) async fn lookup(
        storage: &Storage,
        original: &aos_hub_core::storage_authority::external_object::oci::ExternalOciOriginal,
    ) -> Result<Option<Session>> {
        let key = session_key(&original.fingerprint()?);
        let session: Option<Session> = decode(storage.get::<String>(&key).await?, MAX_SESSION)?;
        if let Some(session) = &session {
            session.validate()?;
            ensure!(
                session.original == *original,
                "external OCI retained original differs"
            );
        }
        Ok(session)
    }

    pub(super) async fn open(
        storage: Storage,
        object: &ObjectConfig,
        config: &Config,
        work: &ExternalOciRequest,
    ) -> Result<Self> {
        let profile = config.profile(&work.original)?;
        let prior_head = load_head(&storage).await?;
        let head = match &prior_head {
            Some(head) => {
                head.validate(object, &work.original.scope)?;
                head.clone()
            }
            None => Head::initialize_floor(
                object,
                &work.original.scope,
                &profile.write_cohort,
                object.clock(),
            )?,
        };
        ensure!(
            head.pending.is_none()
                && head.stage.is_none()
                && head.observation.is_none()
                && head.copy.is_none() && head.mirror.is_none(),
            "another physical operation owns this OCI key"
        );
        let prior = Self::lookup(&storage, &work.original).await?;
        if let Some(selected) = Self::recover(&storage, &work.original).await? {
            ensure!(selected.original == work.original,
                "external OCI requires recovering its first retained original");
        }
        let session = match &prior {
            Some(session) => {
                ensure!(
                    session.configuration == config.digest()?,
                    "external OCI producer configuration changed"
                );
                session.clone()
            }
            None => {
                ensure!(
                    head.oci.is_none() && head.mirror.is_none() && head.visible_receipt.is_none(),
                    "external OCI key has another retained incarnation"
                );
                Session::declare(work.original.clone(), config.digest()?)?
            }
        };
        let owner = session.owner()?;
        ensure!(
            head.oci.as_ref().is_none_or(|existing| existing == &owner),
            "external OCI key has another unresolved original"
        );
        let mut next_head = head;
        if matches!(session.phase, Phase::Declared | Phase::Active) {
            next_head.oci = Some(owner);
        }
        next_head.validate(object, &work.original.scope)?;
        let mut locator = BTreeMap::new();
        locator.insert(selection_key(&work.original.selection_digest()?),
            serde_json::to_string(&work.original.fingerprint()?)?);
        commit(
            &storage,
            prior_head,
            prior,
            next_head.clone(),
            session.clone(),
            locator,
        )
        .await?;
        Ok(Self {
            storage,
            head: next_head,
            session,
        })
    }

    pub(super) async fn install_sources(
        &mut self,
        first: u32,
        sources: &[OciSourceOriginal],
    ) -> Result<()> {
        let original = self.session.original.fingerprint()?;
        let mut records = BTreeMap::new();
        if first < self.session.source_count {
            ensure!(
                first
                    .checked_add(sources.len() as u32)
                    .is_some_and(|end| end <= self.session.source_count),
                "external OCI source replay overlaps new progress"
            );
            for (offset, source) in sources.iter().enumerate() {
                let key = source_key(&original, first + offset as u32);
                let retained: OciSourceOriginal =
                    decode(self.storage.get::<String>(&key).await?, 4096)?
                        .context("external OCI source replay lost its original")?;
                ensure!(retained == *source, "external OCI source replay changed");
            }
            return Ok(());
        }
        let next = self.session.append_sources(first, sources)?;
        for (offset, source) in sources.iter().enumerate() {
            records.insert(
                source_key(&original, first + offset as u32),
                serde_json::to_string(source)?,
            );
        }
        self.retain(self.head.clone(), next, records).await
    }

    pub(super) async fn seal_source(
        &mut self,
        bytes: &aos_hub_core::storage_authority::external_object::oci::OciBytes,
    ) -> Result<()> {
        let next = self.session.seal_source(bytes)?;
        self.retain(self.head.clone(), next, BTreeMap::new()).await
    }

    /// Retains the validated lease floor before any provider dispatch.
    pub(super) async fn retain_floor(
        &mut self,
        floor: aos_hub_core::storage_authority::lease::EpochLeaseFloor,
    ) -> Result<()> {
        let mut next = self.head.clone();
        next.floor = floor;
        self.retain(next, self.session.clone(), BTreeMap::new())
            .await
    }

    pub(super) async fn begin(&mut self, effect: Effect, nonce: String) -> Result<()> {
        let next = self.session.begin(effect, nonce)?;
        self.retain(self.head.clone(), next, BTreeMap::new()).await
    }

    pub(super) async fn acknowledge(&mut self, receipt: Receipt) -> Result<()> {
        let next = self.session.acknowledge(&receipt)?;
        let original = next.original.fingerprint()?;
        let mut records = BTreeMap::new();
        records.insert(
            receipt_key(&original, &receipt.pending.effect_digest),
            serde_json::to_string(&receipt)?,
        );
        if let (
            Effect::Part {
                part_number, bytes, ..
            },
            super::state::Positive::Part { etag },
        ) = (&receipt.pending.effect, &receipt.positive)
        {
            let part = StoredPart {
                part_number: *part_number,
                bytes: bytes.clone(),
                etag: etag.clone(),
                receipt_digest: super::super::protocol::digest(&receipt)?,
            };
            records.insert(
                part_key(&original, *part_number),
                serde_json::to_string(&part)?,
            );
        }
        let mut head = self.head.clone();
        ensure!(
            head.oci.as_ref() == Some(&self.session.owner()?),
            "external OCI owner changed"
        );
        if let Some(closed) = &next.closed {
            let stamp = match &closed.incarnation {
                aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Versioned { guard_stamp, .. }
                | aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Guarded { guard_stamp } => guard_stamp,
            };
            let incarnation = head
                .incarnation
                .get()
                .checked_add(1)
                .context("external OCI guard incarnation exhausted")?;
            ensure!(
                stamp.incarnation.as_str() == incarnation.to_string()
                    && incarnation <= super::super::stage::state::MAX_INCARNATION,
                "external OCI completion guard incarnation differs"
            );
            head.incarnation = WireInteger::new(incarnation);
            head.visible_receipt = Some(VisibleReceipt {
                kind: match next.original.object {
                    aos_hub_core::storage_authority::external_object::oci::OciObjectOriginal::Chunk { .. } => VisibleKind::OciStage,
                    _ => VisibleKind::OciDestination,
                },
                operation_id: original.clone(), receipt_digest: closed.receipt_digest.clone(),
                context_digest: original, incarnation: head.incarnation,
                stage_configuration: Some(next.configuration.clone()),
            });
            head.oci = None;
        } else if next.phase == Phase::Aborted {
            let incarnation = head.incarnation.get().checked_add(1)
                .context("external OCI guard incarnation exhausted")?;
            ensure!(incarnation <= super::super::stage::state::MAX_INCARNATION,
                "external OCI guard incarnation exhausted");
            head.incarnation = WireInteger::new(incarnation);
            head.visible_receipt = None;
            head.oci = None;
        }
        self.retain(head, next, records).await
    }

    pub(super) async fn part(&self, number: u32) -> Result<StoredPart> {
        ensure!(
            number > 0 && number < self.session.next_part,
            "OCI positive part absent"
        );
        let part: StoredPart = decode(
            self.storage
                .get::<String>(&part_key(&self.session.original.fingerprint()?, number))
                .await?,
            MAX_RECORD,
        )?
        .context("OCI positive part receipt lost")?;
        ensure!(
            part.part_number == number,
            "OCI positive part number changed"
        );
        part.bytes.validate()?;
        Ok(part)
    }

    pub(super) async fn parts(&self) -> Result<Vec<PartTag>> {
        let original = self.session.original.fingerprint()?;
        let mut parts = Vec::with_capacity(self.session.next_part.saturating_sub(1) as usize);
        let mut bytes = 0_u64;
        for number in 1..self.session.next_part {
            let part: StoredPart = decode(
                self.storage
                    .get::<String>(&part_key(&original, number))
                    .await?,
                MAX_RECORD,
            )?
            .context("external OCI positive part receipt absent")?;
            ensure!(
                part.part_number == number,
                "external OCI positive part number changed"
            );
            part.bytes.validate()?;
            bytes = bytes
                .checked_add(part.bytes.size)
                .context("external OCI part bytes overflow")?;
            parts.push(PartTag {
                part_number: number,
                etag: part.etag,
            });
        }
        ensure!(
            bytes == self.session.accepted_bytes,
            "external OCI part receipts differ from progress"
        );
        Ok(parts)
    }

    pub(super) async fn source(&self, index: u32) -> Result<OciSourceOriginal> {
        ensure!(
            index < self.session.source_count,
            "external OCI source index absent"
        );
        decode(
            self.storage
                .get::<String>(&source_key(&self.session.original.fingerprint()?, index))
                .await?,
            4096,
        )?
        .context("external OCI retained source descriptor absent")
    }

    async fn retain(
        &mut self,
        head: Head,
        session: Session,
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

/// Reads exact still-visible positive OCI facts without settling any effect.
pub(super) async fn closed_for_lookup(
    storage: &Storage,
    object: &ObjectConfig,
    original: &aos_hub_core::storage_authority::external_object::oci::ExternalOciOriginal,
    expected: &super::state::Closed,
) -> Result<Head> {
    let head = load_head(storage).await?.context("OCI readback lost physical head")?;
    head.validate(object, &original.scope)?;
    let session = Journal::lookup(storage, original).await?
        .context("OCI readback lost positive original")?;
    ensure!(
        head.pending.is_none()
            && head.stage.is_none()
            && head.oci.is_none() && head.mirror.is_none()
            && head.observation.is_none()
            && head.copy.is_none()
            && session.phase == Phase::Closed
            && session.pending.is_none()
            && session.closed.as_ref() == Some(expected),
        "OCI readback is unresolved or replaced"
    );
    let visible = head.visible_receipt.as_ref().context("OCI readback lost visible receipt")?;
    let stamp = match &expected.incarnation {
        aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Versioned { guard_stamp, .. }
        | aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Guarded { guard_stamp } => guard_stamp,
    };
    ensure!(matches!(visible.kind, VisibleKind::OciStage | VisibleKind::OciDestination)
        && visible.context_digest == original.fingerprint()?
        && visible.receipt_digest == expected.receipt_digest
        && visible.stage_configuration.as_ref() == Some(&session.configuration)
        && visible.incarnation == head.incarnation
        && stamp.incarnation.as_str() == head.incarnation.get().to_string(),
        "OCI readback positive incarnation changed");
    Ok(head)
}

/// Advances only the read lease floor while preserving exact positive closure.
pub(super) async fn retain_read_floor(
    storage: &Storage,
    original: &aos_hub_core::storage_authority::external_object::oci::ExternalOciOriginal,
    head: Head,
    floor: aos_hub_core::storage_authority::lease::EpochLeaseFloor,
) -> Result<Head> {
    let session = Journal::lookup(storage, original).await?
        .context("OCI readback lost positive original")?;
    ensure!(session.phase == Phase::Closed && session.pending.is_none(),
        "OCI readback original is unsettled");
    let mut next = head.clone();
    next.floor = floor;
    commit(storage, Some(head), Some(session.clone()), next.clone(), session, BTreeMap::new()).await?;
    Ok(next)
}

pub(super) async fn next_stamp(
    state: &State,
    scope: &StorageAuthorityObjectScope,
) -> Result<StorageGuardStamp> {
    let head = load_head(&state.storage())
        .await?
        .context("OCI completion lost physical owner")?;
    ensure!(
        head.scope == *scope && head.oci.is_some(),
        "OCI completion physical owner differs"
    );
    let next = head
        .incarnation
        .get()
        .checked_add(1)
        .context("OCI guard incarnation exhausted")?;
    ensure!(
        next <= super::super::stage::state::MAX_INCARNATION,
        "OCI guard incarnation exhausted"
    );
    Ok(StorageGuardStamp {
        physical_authority_id: scope.physical_authority_id.clone(),
        incarnation: GuardIncarnation::parse(&next.to_string())?,
    })
}

async fn commit(
    storage: &Storage,
    expected_head: Option<Head>,
    expected_session: Option<Session>,
    head: Head,
    session: Session,
    records: BTreeMap<String, String>,
) -> Result<()> {
    let key = session_key(&session.original.fingerprint()?);
    let encoded = serde_json::to_string(&session)?;
    ensure!(
        encoded.len() <= MAX_SESSION && records.values().all(|value| value.len() <= MAX_RECORD),
        "external OCI compact journal exceeds cell bounds"
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
                let current_head: Option<Head> =
                    decode(transaction_string(&transaction, HEAD).await?, MAX_MESSAGE)
                        .map_err(error)?;
                let current_session: Option<Session> =
                    decode(transaction_string(&transaction, &key).await?, MAX_SESSION)
                        .map_err(error)?;
                if current_head != expected_head || current_session != expected_session {
                    return Err(error("external OCI original/progress CAS refused"));
                }
                for (record_key, value) in &records {
                    if transaction_string(&transaction, record_key)
                        .await?
                        .is_some_and(|prior| prior != *value)
                    {
                        return Err(error("external OCI immutable receipt changed"));
                    }
                }
                for (record_key, value) in records {
                    transaction.put(&record_key, value).await?;
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

pub(super) fn session_key(original: &str) -> String {
    format!("external-oci/session/v1/{original}")
}

fn selection_key(selection: &str) -> String {
    format!("external-oci/selection/v1/{selection}")
}
fn source_key(original: &str, index: u32) -> String {
    format!("external-oci/source/v1/{original}/{index}")
}
fn receipt_key(original: &str, effect: &str) -> String {
    format!("external-oci/receipt/v1/{original}/{effect}")
}
fn part_key(original: &str, number: u32) -> String {
    format!("external-oci/part/v1/{original}/{number}")
}

/// Projects one still-visible OCI source closure without granting Copy authority.
///
/// # Errors
/// Refuses a foreign scope, unresolved/replaced original or changed positive receipt.
pub(in crate::external_object) async fn closed_copy_source(
    storage: &Storage,
    object: &ObjectConfig,
    scope: &StorageAuthorityObjectScope,
) -> Result<aos_hub_core::storage_authority::external_object::copy::source::CopySourceClosure> {
    let head = load_head(storage)
        .await?
        .context("OCI copy source head absent")?;
    head.validate(object, scope)?;
    let visible = head
        .visible_receipt
        .as_ref()
        .context("OCI copy source closure absent")?;
    ensure!(
        matches!(
            visible.kind,
            VisibleKind::OciStage | VisibleKind::OciDestination
        ),
        "OCI copy source belongs to another producer"
    );
    let session: Session = decode(
        storage
            .get::<String>(&session_key(&visible.context_digest))
            .await?,
        MAX_SESSION,
    )?
    .context("OCI copy source original absent")?;
    session.validate()?;
    let closed = session
        .closed
        .as_ref()
        .context("OCI copy source is not closed")?;
    let checked = closed_for_lookup(storage, object, &session.original, closed).await?;
    ensure!(
        checked == head && session.original.scope == *scope,
        "OCI copy source selected another physical key"
    );
    let stamp = match &closed.incarnation {
        aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Versioned { guard_stamp, .. }
        | aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Guarded { guard_stamp } => guard_stamp,
    };
    let closure =
        aos_hub_core::storage_authority::external_object::copy::source::CopySourceClosure {
            guard_stamp: stamp.clone(),
            receipt_digest: closed.receipt_digest.clone(),
            sha256: closed.bytes.sha256.clone(),
            bytes: aos_hub_core::storage_authority::lease::LeaseInteger::new(i64::try_from(
                closed.bytes.size,
            )?)?,
            etag: Some(closed.etag.clone()),
        };
    closure.validate()?;
    Ok(closure)
}
