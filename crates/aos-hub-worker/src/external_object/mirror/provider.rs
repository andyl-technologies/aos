//! Qualified S3 mirror transport with ownership through actual SDK settlement.
//!
//! No provider request is sent until its original effect and validated lease
//! floor are retained. Returned readers attach before any status or identity
//! refusal. Cancellation retains the key/buffer/permit through the pending SDK
//! promise, and never changes the permanent effect journal to a settled state.

use std::{borrow::Cow, rc::Rc};

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    direct_upload::{DirectChecksumAlgorithm, DirectPart, DirectPartChecksum, WireInteger},
    mirror_work::{
        MirrorOriginal, digest,
        external::journal::{MirrorExternalEffect, MirrorExternalPositive, MirrorExternalSession},
    },
    s3surface::{self, S3Surface},
    storage_authority::StorageGuardStamp,
    storage_work::{
        StorageBindingPublication, StorageCredentialSelector, StorageObjectIdentity,
        StorageWorkPlan,
    },
};
use base64::Engine as _;
use md5::Digest as _;
use sha2::{Digest as _, Sha256};
use worker::{Headers, Method, Request, RequestInit, RequestRedirect, State};

use super::super::{config::Config as ObjectConfig, oci::transport};
use super::config::Domain;
use crate::{
    direct_upload::provider_capacity::{self, Class},
    mirror_import::acceptance::AcceptedMirror,
    oci_projection::lifetime::{Owner, Scope},
};

pub(super) struct Provider<'a> {
    pub env: &'a worker::Env,
    pub state: &'a State,
    pub object: &'a ObjectConfig,
    pub domain: &'a Domain,
    pub original: &'a MirrorOriginal,
    pub plan: &'a StorageWorkPlan,
    pub acceptance: &'a AcceptedMirror,
    pub publication: StorageBindingPublication,
}

impl Provider<'_> {
    pub(super) fn current(&self) -> Result<()> {
        let clock = self.object.clock();
        let latest = clock
            .observed_at
            .checked_add(clock.uncertainty)
            .context("mirror provider clock overflow")?;
        let selected = self
            .original
            .external_destination
            .as_ref()
            .context("External mirror transport received Managed original")?;
        let now = u64::try_from(latest)?;
        ensure!(
            selected.issued_at <= now && now < selected.expires_at,
            "mirror original prerequisite cutoff expired"
        );
        self.original.validate_plan(self.plan)?;
        self.plan.validate(&self.plan.deployment_id, latest)?;
        self.publication
            .snapshot
            .authorizes(self.plan, &self.plan.deployment_id, latest)?;
        ensure!(
            self.publication.snapshot.binding_spec_revision()? == selected.binding_spec_revision
                && super::super::config::coordinates(&self.publication.snapshot)?
                    == self.domain.profile.profile.read_cohort.alias.spec,
            "mirror current provider material changed original"
        );
        self.domain.validate_original(self.object, self.original)?;
        self.acceptance.check(now)
    }

    pub(super) fn fresh(&self) -> Rc<dyn Fn() -> Result<()>> {
        let object = self.object.clone();
        let domain = self.domain.clone();
        let original = self.original.clone();
        let plan = self.plan.clone();
        let acceptance = self.acceptance.clone();
        let snapshot = self.publication.snapshot.clone();
        Rc::new(move || {
            let clock = object.clock();
            let latest = clock
                .observed_at
                .checked_add(clock.uncertainty)
                .context("mirror dispatch clock overflow")?;
            let selected = original
                .external_destination
                .as_ref()
                .context("mirror dispatch lost External prerequisite")?;
            let now = u64::try_from(latest)?;
            ensure!(
                selected.issued_at <= now && now < selected.expires_at,
                "mirror original prerequisite cutoff expired"
            );
            original.validate_plan(&plan)?;
            plan.validate(&plan.deployment_id, latest)?;
            snapshot.authorizes(&plan, &plan.deployment_id, latest)?;
            ensure!(
                snapshot.binding_spec_revision()? == selected.binding_spec_revision,
                "mirror provider material changed original"
            );
            domain.validate_original(&object, &original)?;
            acceptance.check(now)
        })
    }

    pub(super) fn surface(&self, read: bool) -> Result<S3Surface> {
        self.current()?;
        let cohort = if read {
            &self.domain.profile.profile.read_cohort
        } else {
            &self.domain.profile.profile.write_cohort
        };
        let selector = StorageCredentialSelector {
            purpose: if read { "read" } else { "write" }.into(),
            generation: cohort.credential.generation.get(),
        };
        let now = self.object.clock().observed_at;
        let credential =
            self.publication
                .credential_text(&selector, &self.plan.deployment_id, now)?;
        // The original commits the full stage/destination key. An empty surface
        // sub-prefix avoids accidentally assigning a placement prefix twice.
        S3Surface::from_snapshot(
            &self.publication.snapshot,
            &self.plan.deployment_id,
            "",
            Some(&credential),
            now,
        )
    }

    pub(super) fn relative_key<'a>(&self, full_key: &'a str) -> Result<&'a str> {
        let prefix = &self.publication.snapshot.object_prefix;
        if prefix.is_empty() {
            return Ok(full_key);
        }
        full_key
            .strip_prefix(&format!("{prefix}/"))
            .context("mirror key escapes exact physical binding prefix")
    }

    pub(super) async fn mutation<R: 'static>(
        &self,
        session: &MirrorExternalSession,
        payload: Option<Rc<Vec<u8>>>,
        stamp: StorageGuardStamp,
        root: Rc<Owner<R>>,
        lease_check: Rc<dyn Fn() -> Result<()>>,
    ) -> Result<MirrorExternalPositive> {
        self.current()?;
        session.validate()?;
        ensure!(
            session.original == *self.original,
            "mirror pending transport original changed"
        );
        let pending = session
            .pending
            .as_ref()
            .context("mirror effect was not retained")?;
        let surface = self.surface(false)?;
        let full_key = session.key();
        let key = self.relative_key(&full_key)?;
        let now = self.object.clock().observed_at;
        let headers = Headers::new();
        let mut body: Option<Cow<'_, [u8]>> = None;
        let (url, method) = match &pending.effect {
            MirrorExternalEffect::Create => {
                ensure!(
                    payload.is_none(),
                    "mirror Create cannot contain object bytes"
                );
                let signed = surface.direct_create_multipart_request(
                    key,
                    DirectChecksumAlgorithm::Md5,
                    now,
                    30,
                )?;
                for header in signed.required_headers {
                    headers.set(&header.name, &header.value)?;
                }
                (signed.url, Method::Post)
            }
            MirrorExternalEffect::EmptyPut => {
                ensure!(
                    payload.is_none(),
                    "empty mirror PUT cannot contain object bytes"
                );
                let signed = surface.external_oci_empty_put_request(key, now)?;
                for header in signed.required_headers {
                    headers.set(&header.name, &header.value)?;
                }
                body = Some(Cow::Borrowed(&[]));
                (signed.url, Method::Put)
            }
            MirrorExternalEffect::Part { part, checksum_md5 } => {
                let bytes = payload.as_ref().context("mirror part body absent")?;
                ensure!(
                    bytes.len() as u64 == part.size
                        && hex::encode(Sha256::digest(bytes.as_slice())) == part.sha256
                        && base64::engine::general_purpose::STANDARD
                            .encode(md5::Md5::digest(bytes.as_slice()))
                            == *checksum_md5,
                    "mirror part changed its retained byte proof"
                );
                let direct = DirectPart {
                    part_number: part.part_number,
                    offset: WireInteger::new(
                        (u64::from(part.part_number) - 1)
                            * aos_hub_core::mirror_work::MIRROR_PART_BYTES,
                    ),
                    byte_size: WireInteger::new(part.size),
                    sha256: part.sha256.clone(),
                    checksum: DirectPartChecksum {
                        algorithm: DirectChecksumAlgorithm::Md5,
                        value: checksum_md5.clone(),
                    },
                };
                let upload = if session.destination {
                    &session.progress.destination_upload_id
                } else {
                    &session.progress.stage_upload_id
                };
                let signed = surface.direct_upload_part_request(
                    key,
                    upload
                        .as_deref()
                        .context("mirror positive UploadId absent")?,
                    &direct,
                    now,
                    30,
                )?;
                for header in signed.required_headers {
                    headers.set(&header.name, &header.value)?;
                }
                body = Some(Cow::Borrowed(bytes.as_slice()));
                (signed.url, Method::Put)
            }
            MirrorExternalEffect::Complete {
                upload_id,
                parts_digest,
            } => {
                ensure!(
                    payload.is_none(),
                    "mirror Complete cannot contain object bytes"
                );
                let manifest = if session.destination {
                    &session.progress.destination_parts
                } else {
                    &session.progress.stage_parts
                };
                ensure!(
                    digest(manifest)? == *parts_digest,
                    "mirror Complete manifest changed"
                );
                let parts: Vec<aos_hub_core::surface_write::PartTag> = manifest
                    .iter()
                    .map(|part| aos_hub_core::surface_write::PartTag {
                        part_number: part.part_number,
                        etag: part.etag.clone(),
                    })
                    .collect();
                body = Some(Cow::Owned(
                    s3surface::complete_multipart_xml(&parts)?.into_bytes(),
                ));
                headers.set("content-type", "application/xml")?;
                (
                    surface.multipart_url("complete", key, Some(upload_id), None, now)?,
                    Method::Post,
                )
            }
        };
        aos_hub_core::url_guard::is_safe_remote_url(&url)?;
        let mut init = RequestInit::new();
        init.with_method(method)
            .with_headers(headers)
            .with_redirect(RequestRedirect::Manual);
        if let Some(body) = &body {
            init.with_body(Some(js_sys::Uint8Array::from(body.as_ref()).into()));
        }
        let request = Request::new_with_init(&url, &init)?;
        drop(body);
        let current = self.fresh();
        let fresh: Rc<dyn Fn() -> Result<()>> = Rc::new(move || {
            current()?;
            lease_check()
        });
        let permit = provider_capacity::acquire_class_checked(1, Class::Bulk, &|| {
            root.check_open()?;
            fresh()
        })
        .await?;
        root.check_open()?;
        fresh()?;
        let owner = Owner::new((Rc::clone(&root), permit, payload));
        let _scope = Scope(Rc::clone(&owner));
        let (response, reader) =
            transport::fetch_owned(self.state, request, Rc::clone(&owner), Rc::clone(&fresh))
                .await?;
        ensure!(
            response.status_code() == 200,
            "mirror mutation has no positive provider receipt"
        );
        match &pending.effect {
            MirrorExternalEffect::Create => {
                let xml = metadata(
                    reader.context("mirror Create receipt stream absent")?,
                    &fresh,
                )
                .await?;
                let upload_id = s3surface::parse_direct_create_multipart(
                    &xml,
                    &self.publication.snapshot.object_bucket,
                    &full_key,
                )?;
                Ok(MirrorExternalPositive::Created { upload_id })
            }
            MirrorExternalEffect::Part { .. } => {
                let etag = response
                    .headers()
                    .get("etag")?
                    .context("mirror part ETag absent")?;
                aos_hub_core::surface_write::strong_if_match_etag(&etag)?;
                Ok(MirrorExternalPositive::Part { etag })
            }
            MirrorExternalEffect::Complete { .. } | MirrorExternalEffect::EmptyPut => {
                let version = response
                    .headers()
                    .get("x-amz-version-id")?
                    .filter(|version| version != "null");
                self.domain.require_version(version.as_deref())?;
                let etag = if matches!(pending.effect, MirrorExternalEffect::Complete { .. }) {
                    let xml = metadata(
                        reader.context("mirror Complete receipt stream absent")?,
                        &fresh,
                    )
                    .await?;
                    s3surface::parse_direct_complete_multipart(
                        &xml,
                        &self.publication.snapshot.object_bucket,
                        &full_key,
                    )?
                    .etag
                } else {
                    response
                        .headers()
                        .get("etag")?
                        .context("mirror empty PUT ETag absent")?
                };
                aos_hub_core::surface_write::strong_if_match_etag(&etag)?;
                Ok(MirrorExternalPositive::Completed {
                    object: StorageObjectIdentity {
                        key: full_key,
                        provider_version: version,
                        etag,
                        size: self.original.verification.size(),
                    },
                    guard_stamp: stamp,
                })
            }
        }
    }
}

pub(super) async fn metadata(
    reader: Rc<crate::direct_digest::Reader>,
    fresh: &Rc<dyn Fn() -> Result<()>>,
) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let (view, done) = transport::bounded(reader.read(), fresh.as_ref()).await?;
        ensure!(
            bytes
                .len()
                .checked_add(view.length() as usize)
                .is_some_and(|count| count <= 16 * 1024),
            "mirror provider receipt exceeds metadata bound"
        );
        bytes.extend_from_slice(&view.to_vec());
        if done {
            break;
        }
    }
    Ok(String::from_utf8(bytes)?)
}

/// Retains one actual Write lease floor and intent before invoking its SDK effect.
pub(super) async fn effect<R: 'static>(
    provider: &Provider<'_>,
    journal: &mut super::storage::Journal,
    effect: MirrorExternalEffect,
    payload: Option<Rc<Vec<u8>>>,
    root: Rc<Owner<R>>,
) -> Result<()> {
    use aos_hub_core::storage_authority::lease::LeaseEffect;
    use rand::TryRngCore as _;

    provider.current()?;
    let cohort = &provider.domain.profile.profile.write_cohort;
    let token = super::super::stage::acquire_configured_lease(
        provider.env,
        provider.object,
        &provider.domain.issuer_installation,
        cohort,
        &cohort.admitted_prefix,
    )
    .await?;
    provider.current()?;
    let allowed = match effect {
        MirrorExternalEffect::Create => LeaseEffect::MultipartCreate,
        MirrorExternalEffect::EmptyPut => LeaseEffect::Put,
        MirrorExternalEffect::Part { .. } => LeaseEffect::MultipartPart,
        MirrorExternalEffect::Complete { .. } => LeaseEffect::MultipartComplete,
    };
    let validated = provider.object.verifier()?.validate_lease(
        token.as_bytes(),
        cohort,
        &provider.object.timing_profile,
        &journal.head.floor,
        &journal.session.key(),
        allowed,
        provider.object.clock(),
    )?;
    let stamp = journal.next_stamp()?;
    let mut random = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| anyhow::anyhow!("mirror dispatch randomness unavailable"))?;
    journal
        .begin(effect, hex::encode(random), validated.next_floor)
        .await?;

    let object = provider.object.clone();
    let cohort = cohort.clone();
    let floor = journal.head.floor.clone();
    let key = journal.session.key();
    let before = Rc::new(move || {
        object.verifier()?.validate_lease(
            token.as_bytes(),
            &cohort,
            &object.timing_profile,
            &floor,
            &key,
            allowed,
            object.clock(),
        )?;
        Ok(())
    });
    let positive = provider
        .mutation(&journal.session, payload, stamp, root, before)
        .await?;
    let receipt = aos_hub_core::mirror_work::external::journal::MirrorExternalReceipt {
        original_digest: digest(&journal.session.original)?,
        pending: journal
            .session
            .pending
            .clone()
            .context("mirror pending attempt lost")?,
        positive,
    };
    // An error, response loss or cancellation above leaves both the exact
    // original and floor retained. Only this actual positive receipt clears it.
    journal.acknowledge(receipt).await
}
