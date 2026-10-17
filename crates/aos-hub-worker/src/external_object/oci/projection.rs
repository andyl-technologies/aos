//! Conditional external OCI document inspection on the permanent full-key guard.
//!
//! The reader requires a retained positive OCI completion and the exact current
//! visible guard incarnation before any SDK operation. A real provider version
//! remains distinct from a qualified versionless guard stamp. Metadata parsing
//! occurs only after full EOF, byte count and SHA-256 verification; no object
//! body or private provider material enters the signed reply.

use std::{rc::Rc, time::Duration};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    oci_projection::{guard::*, OciDocumentProjection, OciProjectionSource},
    s3surface::S3Surface,
    storage_authority::{external_object::oci::OciProviderIncarnation, lease::LeaseEffect},
    storage_work::{StorageBindingPublication, StorageCredentialSelector, StorageObjectIdentity},
};
use worker::{Headers, Method, Request, RequestInit, RequestRedirect, Response};

use super::super::{
    config::{configured, Config as ObjectConfig},
    storage::ExternalObjectGuard,
};
use super::{config, storage, transport};
use crate::oci_projection::lifetime::{Owner, Scope};

pub(super) const PHYSICAL_PATH: &str = "/oci-document-projection";

impl ExternalObjectGuard {
    pub(in crate::external_object) async fn oci_projection_fetch(
        &self,
        request: &mut Request,
    ) -> worker::Result<Response> {
        match self.oci_projection_handle(request).await {
            Ok(response) => Ok(response),
            Err(_) => Response::error("external OCI document is unavailable or unsettled", 409),
        }
    }

    async fn oci_projection_handle(&self, request: &mut Request) -> Result<Response> {
        ensure!(request.url()?.path() == PHYSICAL_PATH,
            "external OCI projection route changed");
        let (lookup, _, _) = crate::oci_projection::authenticate(request, &self.env).await?;
        let OciProjectionSource::External { original, closed } = &lookup.source else {
            anyhow::bail!("external OCI guard requires an external original");
        };
        let object = configured(&self.env)?.context("external object consumer disabled")?;
        let current_lookup = || {
            lookup.validate(&lookup.deployment_id, crate::direct_upload::config::guard_latest_now(&self.env)?)
        };
        let name = original.scope.guard_name()?;
        ensure!(original.scope.guard_namespace_id == object.guard_namespace_id
            && self.env.durable_object(super::super::storage::BINDING)?
                .id_from_name(&name)?.to_string() == self.state.id().to_string(),
            "external OCI lookup addressed another permanent guard");
        let gate = loop {
            current_lookup()?;
            if let Some(gate) = self.gate.try_lock_owned() { break gate; }
            worker::Delay::from(Duration::from_millis(50)).await;
        };
        current_lookup()?;
        crate::direct_guard::deny_legacy(&self.state.storage()).await?;
        let configured = config::configured(&self.env, &object)?;
        let profile = configured.profile(original)?.clone();
        let accepted = config::require(&self.env, &object, &profile, &original.writer.placement_prefix).await?;
        current_lookup()?;
        let publication = crate::hybrid_binding::resolve_for_delivery(&self.env,
            original.writer.binding_id.get(), original.writer.binding_resource_version.get()).await?;
        let mut head = storage::closed_for_lookup(&self.state.storage(), &object, original, closed).await?;
        let token = super::super::stage::acquire_configured_lease(&self.env, &object,
            &profile.issuer_installation, &profile.read_cohort, &profile.read_cohort.admitted_prefix).await?;
        let observed_latest = latest(&object)?;
        profile.validate_snapshot(&publication.snapshot, observed_latest)?;
        accepted.current(&object)?;
        current_lookup()?;
        let verifier = object.verifier()?;
        let validated = verifier.validate_lease(token.as_bytes(), &profile.read_cohort,
            &object.timing_profile, &head.floor, &lookup.key, LeaseEffect::Head, object.clock())?;
        let validated_get = verifier.validate_lease(token.as_bytes(), &profile.read_cohort,
            &object.timing_profile, &validated.next_floor, &lookup.key, LeaseEffect::Read, object.clock())?;
        head = storage::retain_read_floor(&self.state.storage(), original, head, validated_get.next_floor).await?;

        let selected = lookup.clone();
        let current_object = object.clone();
        let current_profile = profile.clone();
        let current_snapshot = publication.snapshot.clone();
        let current_accepted = accepted.clone();
        let fresh: Rc<dyn Fn() -> Result<()>> = Rc::new(move || {
            selected.validate(&selected.deployment_id,
                u64::try_from(latest(&current_object)?).context("external OCI clock before UTC")?)?;
            current_profile.validate_snapshot(&current_snapshot, latest(&current_object)?)?;
            current_accepted.current(&current_object)?;
            for effect in [LeaseEffect::Head, LeaseEffect::Read] {
                current_object.verifier()?.validate_lease(token.as_bytes(),
                    &current_profile.read_cohort, &current_object.timing_profile, &head.floor,
                    &selected.key, effect, current_object.clock())?;
            }
            Ok(())
        });
        let buffer = crate::mirror_import::buffers::acquire(false, &|| fresh()).await?;
        let capacity = crate::direct_upload::provider_capacity::acquire_class_checked(1,
            crate::direct_upload::provider_capacity::Class::Metadata, &|| fresh()).await?;
        let owner = Owner::new((gate, buffer, capacity));
        let _scope = Scope(Rc::clone(&owner));
        fresh()?;
        let surface = surface(&object, &publication, original, &profile.read_cohort)?;
        let prefix = aos_hub_core::keymap::r2_key(&original.writer.binding_prefix,
            &original.writer.placement_prefix);
        let key = if prefix.is_empty() { lookup.key.as_str() } else {
            lookup.key.strip_prefix(&format!("{prefix}/"))
                .context("external OCI read escapes exact physical writer")?
        };
        let version = match &closed.incarnation {
            OciProviderIncarnation::Versioned { provider_version, .. } => Some(provider_version.as_str()),
            OciProviderIncarnation::Guarded { .. } => {
                ensure!(profile.versionless_conditional_reads,
                    "external OCI versionless observation is not qualified");
                None
            }
        };

        // A child owns each returned SDK reader. Closing HEAD cannot close the
        // root key/capacity owner that must survive through the subsequent GET.
        let head_owner = Owner::new(Rc::clone(&owner));
        let head_scope = Scope(Rc::clone(&head_owner));
        let signed = surface.oci_conditional_read_request(key, true, &closed.etag, version, None,
            object.clock().observed_at)?;
        let (response, _) = transport::fetch_owned(&self.state, provider_request(signed, Method::Head)?,
            head_owner, Rc::clone(&fresh)).await?;
        validate_identity(&response, &lookup)?;
        drop(head_scope);
        fresh()?;
        let read_owner = Owner::new(Rc::clone(&owner));
        let _read_scope = Scope(Rc::clone(&read_owner));
        let signed = surface.oci_conditional_read_request(key, false, &closed.etag, version, None,
            object.clock().observed_at)?;
        let (response, reader) = transport::fetch_owned(&self.state, provider_request(signed, Method::Get)?,
            Rc::clone(&read_owner), Rc::clone(&fresh)).await?;
        // fetch_owned attaches cancellation before validating response identity.
        let identity = validate_identity(&response, &lookup)?;
        let reader = reader.context("external OCI conditional response body absent")?;
        let mut bytes = Vec::with_capacity(usize::try_from(lookup.descriptor.size)?);
        loop {
            let (view, done) = transport::bounded(reader.read(), &|| {
                owner.check_open()?;
                read_owner.check_open()?;
                fresh()
            }).await?;
            ensure!(bytes.len().checked_add(view.length() as usize)
                .is_some_and(|size| size as u64 <= lookup.descriptor.size),
                "external OCI response exceeds exact document size");
            bytes.extend_from_slice(&view.to_vec());
            if done { break; }
        }
        let projection = OciDocumentProjection::from_stored_bytes(&lookup.descriptor, &bytes)?;
        fresh()?;
        storage::closed_for_lookup(&self.state.storage(), &object, original, closed).await?;
        fresh()?;
        let reply = OciProjectionReply { request: lookup,
            object: identity, projection,
            observed_at: crate::direct_upload::config::guard_latest_now(&self.env)?,
        };
        let signed = sign_oci_projection_reply(&super::super::storage::key(&self.env)?, &reply)?;
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        headers.set("cache-control", "private, no-store")?;
        headers.set(OCI_PROJECTION_SIGNATURE_HEADER, &signed.signature)?;
        Ok(Response::from_bytes(signed.body)?.with_headers(headers))
    }
}

fn latest(object: &ObjectConfig) -> Result<i64> {
    let clock = object.clock();
    clock.observed_at.checked_add(clock.uncertainty).context("external OCI clock overflow")
}

fn surface(
    object: &ObjectConfig,
    publication: &StorageBindingPublication,
    original: &aos_hub_core::storage_authority::external_object::oci::ExternalOciOriginal,
    cohort: &aos_hub_core::storage_authority::lease::LeaseCohort,
) -> Result<S3Surface> {
    let credential = publication.credential_text(&StorageCredentialSelector {
        purpose: "read".into(), generation: cohort.credential.generation.get(),
    }, &original.deployment_id, object.clock().observed_at)?;
    S3Surface::from_snapshot(&publication.snapshot, &original.deployment_id,
        &original.writer.placement_prefix, Some(&credential), object.clock().observed_at)
}

fn provider_request(signed: aos_hub_core::sigv4::DirectSignedProviderRequest, method: Method) -> Result<Request> {
    aos_hub_core::url_guard::is_safe_remote_url(&signed.url)?;
    let headers = Headers::new();
    for header in signed.required_headers { headers.set(&header.name, &header.value)?; }
    let mut init = RequestInit::new();
    init.with_method(method).with_redirect(RequestRedirect::Manual).with_headers(headers);
    Ok(Request::new_with_init(&signed.url, &init)?)
}

fn validate_identity(response: &Response, lookup: &OciProjectionLookup) -> Result<StorageObjectIdentity> {
    ensure!(response.status_code() == 200, "external OCI conditional observation refused");
    let size: u64 = response.headers().get("content-length")?
        .context("external OCI conditional length absent")?.parse()?;
    let etag = response.headers().get("etag")?.context("external OCI conditional ETag absent")?;
    let version = response.headers().get("x-amz-version-id")?;
    let version = match &lookup.source {
        OciProjectionSource::External { closed, .. } => match &closed.incarnation {
            OciProviderIncarnation::Guarded { .. } => {
                ensure!(version.as_deref().is_none_or(|version| version == "null"),
                    "external OCI versionless response acquired another identity");
                None
            }
            OciProviderIncarnation::Versioned { .. } => version,
        },
        _ => anyhow::bail!("external OCI response needs exact source kind"),
    };
    let identity = StorageObjectIdentity { key: lookup.key.clone(), size, etag, provider_version: version };
    lookup.source.validate_object(&identity)?;
    ensure!(response.headers().get("content-encoding")?.as_deref()
        .is_none_or(|encoding| encoding.eq_ignore_ascii_case("identity")),
        "external OCI document unexpectedly transformed");
    Ok(identity)
}
