//! Exact OCI multipart transport under fresh original, lease and byte bounds.
//!
//! No URL or credential enters the retained journal or reply. The caller owns
//! a permanent pending effect before invoking a mutation. Deadline closure
//! stops new dispatch while a pending Fetch retains the real key and capacity.

use std::{borrow::Cow, future::Future, rc::Rc, time::Duration};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    direct_upload::{DirectChecksumAlgorithm, DirectPart, DirectPartChecksum, WireInteger},
    s3surface::{self, S3Surface},
    storage_authority::external_object::oci::{
        control::ExternalOciRequest, qualification::ExternalOciProfile,
    },
    storage_work::{StorageBindingPublication, StorageCredentialSelector},
};
use base64::Engine as _;
use futures_util::{
    future::{select, Either},
};
use js_sys::Uint8Array;
use md5::Digest as _;
use sha2::{Digest as _, Sha256};
use worker::{Headers, Method, Request, RequestInit, RequestRedirect, Response, State};

use super::super::config::{coordinates, Config as ObjectConfig};
use super::{
    config::Accepted,
    state::{Effect, Positive, Session},
};
use crate::{
    direct_upload::provider_capacity::{self, Class},
    oci_projection::lifetime::{Owner, Scope},
};

const MAX_PROVIDER_METADATA: usize = 16 * 1024;

pub(super) struct Provider<'a> {
    pub state: &'a State,
    pub object: &'a ObjectConfig,
    pub profile: &'a ExternalOciProfile,
    pub work: &'a ExternalOciRequest,
    pub accepted: &'a Accepted,
    pub publication: StorageBindingPublication,
}

impl Provider<'_> {
    pub(super) fn current(&self) -> Result<()> {
        let clock = self.object.clock();
        let latest = clock
            .observed_at
            .checked_add(clock.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("external OCI clock overflow"))?;
        self.work
            .validate_snapshot(&self.publication.snapshot, latest)?;
        self.profile
            .validate_snapshot(&self.publication.snapshot, latest)?;
        ensure!(
            coordinates(&self.publication.snapshot)? == self.profile.read_cohort.alias.spec,
            "external OCI provider alias changed"
        );
        self.accepted.current(self.object)
    }

    fn surface(&self, read: bool) -> Result<S3Surface> {
        self.current()?;
        let cohort = if read {
            &self.profile.read_cohort
        } else {
            &self.profile.write_cohort
        };
        let selector = StorageCredentialSelector {
            purpose: if read { "read" } else { "write" }.into(),
            generation: cohort.credential.generation.get(),
        };
        let credential = self.publication.credential_text(
            &selector,
            &self.work.original.deployment_id,
            self.object.clock().observed_at,
        )?;
        S3Surface::from_snapshot(
            &self.publication.snapshot,
            &self.work.original.deployment_id,
            &self.work.original.writer.placement_prefix,
            Some(&credential),
            self.object.clock().observed_at,
        )
    }

    fn relative_key(&self) -> Result<&str> {
        let writer = &self.work.original.writer;
        let prefix = aos_hub_core::keymap::r2_key(&writer.binding_prefix, &writer.placement_prefix);
        if prefix.is_empty() {
            return Ok(&self.work.original.scope.full_key);
        }
        self.work
            .original
            .scope
            .full_key
            .strip_prefix(&format!("{prefix}/"))
            .context("external OCI destination escapes exact writer prefix")
    }

    /// Executes only the already journaled exact multipart effect.
    pub(super) async fn mutation<R: 'static>(
        &self,
        session: &Session,
        body: Option<&[u8]>,
        parts: &[aos_hub_core::surface_write::PartTag],
        owner: Rc<Owner<R>>,
        before_dispatch: Rc<dyn Fn() -> Result<()>>,
    ) -> Result<Positive> {
        session.validate()?;
        let pending = session
            .pending
            .as_ref()
            .context("external OCI effect is not retained")?;
        ensure!(
            session.original == self.work.original,
            "external OCI transport original differs from pending"
        );
        let surface = self.surface(false)?;
        let key = self.relative_key()?;
        let now = self.object.clock().observed_at;
        let headers = Headers::new();
        let mut encoded: Option<Cow<'_, [u8]>> = None;
        let (url, method) = match &pending.effect {
            Effect::EmptyPut { .. } => {
                ensure!(body.is_none(), "empty OCI PUT cannot contain object bytes");
                let signed = surface.external_oci_empty_put_request(key, now)?;
                for header in signed.required_headers {
                    headers.set(&header.name, &header.value)?;
                }
                encoded = Some(Cow::Borrowed(&[]));
                (signed.url, Method::Put)
            }
            Effect::Create => {
                ensure!(body.is_none(), "unexpected OCI Create body");
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
            Effect::Part {
                part_number,
                bytes,
                checksum_md5,
                ..
            } => {
                let payload = body.context("external OCI part body absent")?;
                ensure!(
                    payload.len() as u64 == bytes.size,
                    "external OCI part body length differs"
                );
                ensure!(
                    hex::encode(Sha256::digest(payload)) == bytes.sha256
                        && base64::engine::general_purpose::STANDARD
                            .encode(md5::Md5::digest(payload))
                            == *checksum_md5,
                    "external OCI part body differs from retained cryptographic proof"
                );
                let part = DirectPart {
                    part_number: *part_number,
                    offset: WireInteger::new(session.accepted_bytes),
                    byte_size: WireInteger::new(bytes.size),
                    sha256: bytes.sha256.clone(),
                    checksum: DirectPartChecksum {
                        algorithm: DirectChecksumAlgorithm::Md5,
                        value: checksum_md5.clone(),
                    },
                };
                let signed = surface.direct_upload_part_request(
                    key,
                    session
                        .provider_upload_id
                        .as_deref()
                        .context("OCI UploadId absent")?,
                    &part,
                    now,
                    30,
                )?;
                for header in signed.required_headers {
                    headers.set(&header.name, &header.value)?;
                }
                encoded = Some(Cow::Borrowed(payload));
                (signed.url, Method::Put)
            }
            Effect::Complete { parts_digest, .. } => {
                ensure!(
                    body.is_none()
                        && !parts.is_empty()
                        && super::super::protocol::digest(&parts)? == *parts_digest,
                    "external OCI Complete manifest differs"
                );
                encoded = Some(Cow::Owned(
                    s3surface::complete_multipart_xml(parts)?.into_bytes(),
                ));
                headers.set("content-type", "application/xml")?;
                (
                    surface.multipart_url(
                        "complete",
                        key,
                        session.provider_upload_id.as_deref(),
                        None,
                        now,
                    )?,
                    Method::Post,
                )
            }
            Effect::Abort => {
                ensure!(body.is_none(), "unexpected OCI Abort body");
                (
                    surface.multipart_url(
                        "abort",
                        key,
                        session.provider_upload_id.as_deref(),
                        None,
                        now,
                    )?,
                    Method::Delete,
                )
            }
        };
        aos_hub_core::url_guard::is_safe_remote_url(&url)?;
        let mut init = RequestInit::new();
        init.with_method(method)
            .with_redirect(RequestRedirect::Manual)
            .with_headers(headers);
        if let Some(body) = &encoded {
            init.with_body(Some(Uint8Array::from(body.as_ref()).into()));
        }
        let request = Request::new_with_init(&url, &init)?;
        let capacity = provider_capacity::acquire_class_checked(1, Class::Bulk, &|| {
            owner.check_open()?;
            self.current()?;
            before_dispatch()
        })
        .await?;
        let response_owner = Owner::new((Rc::clone(&owner), capacity));
        let _scope = Scope(Rc::clone(&response_owner));
        owner.check_open()?;
        self.current()?;
        before_dispatch()?;
        let object = self.object.clone();
        let profile = self.profile.clone();
        let work = self.work.clone();
        let snapshot = self.publication.snapshot.clone();
        let accepted = self.accepted.clone();
        let fresh = Rc::new(move || {
            let clock = object.clock();
            let latest = clock
                .observed_at
                .checked_add(clock.uncertainty)
                .context("external OCI dispatch clock overflow")?;
            work.validate_snapshot(&snapshot, latest)?;
            profile.validate_snapshot(&snapshot, latest)?;
            accepted.current(&object)?;
            before_dispatch()
        });
        let (response, reader) = self
            .fetch_owned(request, Rc::clone(&response_owner), fresh)
            .await?;
        ensure!(
            response.status_code()
                == match &pending.effect {
                    Effect::Abort => 204,
                    _ => 200,
                },
            "external OCI provider mutation lacks a positive receipt"
        );
        match &pending.effect {
            Effect::Create => {
                let xml = self
                    .metadata(reader.context("OCI Create receipt stream absent")?)
                    .await?;
                let upload_id = s3surface::parse_direct_create_multipart(
                    &xml,
                    &self.publication.snapshot.object_bucket,
                    &session.original.scope.full_key,
                )?;
                Ok(Positive::Created { upload_id })
            }
            Effect::Part { .. } => {
                let etag = response
                    .headers()
                    .get("etag")?
                    .context("OCI part ETag absent")?;
                ensure!(
                    aos_hub_core::surface_write::strong_if_match_etag(&etag)? == etag,
                    "external OCI part ETag malformed"
                );
                Ok(Positive::Part { etag })
            }
            Effect::EmptyPut { .. } => {
                let etag = response.headers().get("etag")?.context("OCI empty PUT ETag absent")?;
                ensure!(aos_hub_core::surface_write::strong_if_match_etag(&etag)? == etag,
                    "OCI empty PUT lacks a strong provider identity");
                let version = response.headers().get("x-amz-version-id")?;
                let stamp = super::storage::next_stamp(self.state, &session.original.scope).await?;
                let incarnation = match version {
                    Some(provider_version) if aos_hub_core::storage_work::valid_provider_version(&provider_version) =>
                        aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Versioned {
                            provider_version, guard_stamp: stamp,
                        },
                    version if self.profile.versionless_conditional_reads
                        && version.as_deref().is_none_or(|version| version == "null") =>
                        aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Guarded {
                            guard_stamp: stamp,
                        },
                    _ => anyhow::bail!("OCI empty PUT lacks its qualified provider incarnation"),
                };
                Ok(Positive::Completed { etag, incarnation })
            }
            Effect::Complete { .. } => {
                let version = response.headers().get("x-amz-version-id")?;
                let xml = self
                    .metadata(reader.context("OCI Complete receipt stream absent")?)
                    .await?;
                let object = s3surface::parse_direct_complete_multipart(
                    &xml,
                    &self.publication.snapshot.object_bucket,
                    &session.original.scope.full_key,
                )?;
                let stamp = super::storage::next_stamp(self.state, &session.original.scope).await?;
                let incarnation = match version {
                    Some(provider_version) if aos_hub_core::storage_work::valid_provider_version(&provider_version) => aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Versioned {
                        provider_version, guard_stamp: stamp,
                    },
                    version if self.profile.versionless_conditional_reads
                        && version.as_deref().is_none_or(|version| version == "null") =>
                        aos_hub_core::storage_authority::external_object::oci::OciProviderIncarnation::Guarded { guard_stamp: stamp },
                    _ => anyhow::bail!("external OCI completion has no qualified provider identity"),
                };
                incarnation.validate(session.original.scope.physical_authority_id.as_str())?;
                Ok(Positive::Completed {
                    etag: object.etag,
                    incarnation,
                })
            }
            Effect::Abort => Ok(Positive::Aborted),
        }
    }

    async fn fetch_owned<R: 'static>(
        &self,
        request: Request,
        owner: Rc<Owner<R>>,
        fresh: Rc<dyn Fn() -> Result<()>>,
    ) -> Result<(Response, Option<Rc<crate::direct_digest::Reader>>)> {
        super::transport::fetch_owned(self.state, request, owner, fresh).await
    }

    async fn metadata(&self, reader: Rc<crate::direct_digest::Reader>) -> Result<String> {
        let mut bytes = Vec::new();
        loop {
            let (view, done) = self.bounded(reader.read()).await?;
            ensure!(
                bytes
                    .len()
                    .checked_add(view.length() as usize)
                    .is_some_and(|size| size <= MAX_PROVIDER_METADATA),
                "external OCI receipt oversized"
            );
            bytes.extend_from_slice(&view.to_vec());
            if done {
                break;
            }
        }
        Ok(String::from_utf8(bytes)?)
    }

    pub(super) async fn bounded<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        self.current()?;
        let timer = async {
            loop {
                worker::Delay::from(Duration::from_millis(50)).await;
                self.current()?;
            }
        };
        futures_util::pin_mut!(work, timer);
        match select(work, timer).await {
            Either::Left((value, _)) => {
                self.current()?;
                value
            }
            Either::Right((result, _)) => result,
        }
    }
}
