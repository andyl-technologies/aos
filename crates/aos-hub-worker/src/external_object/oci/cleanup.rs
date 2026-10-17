//! Same-guard terminal private-chunk deletion with permanent positive-only replay.
//!
//! Source closure is read from OCI KV, never inferred from HEAD. The existing
//! compact pending turn is committed before DELETE and retained through unknown
//! outcomes. Only an exact versioned DELETE clears visibility.

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    s3surface::S3Surface,
    storage_authority::{external_object::oci::cleanup::*, lease::LeaseEffect},
    storage_work::{StorageCredentialSelector, StorageWorkKey},
};
use std::{rc::Rc, time::Duration};
use worker::{Env, Headers, Method, Request, RequestInit, Response, Storage};

use super::super::{
    config::{Config, configured},
    protocol::{MAX_MESSAGE, Receipt, digest},
    state::{Head, VisibleKind},
    storage::{BINDING, ExternalObjectGuard, HEAD, decode, error, load_head, transaction_string},
};
use super::{cleanup_state::Record, state::Session};
use crate::oci_projection::lifetime::{Owner, Scope};

const PHYSICAL: &str = "/oci-cleanup";

fn latest(env: &Env) -> Result<i64> {
    i64::try_from(crate::direct_upload::config::guard_latest_now(env)?)
        .context("terminal OCI cleanup clock overflow")
}

async fn authenticate(
    request: &mut Request,
    env: &Env,
) -> Result<(OciCleanupRequest, Vec<u8>, String)> {
    ensure!(
        request.method() == Method::Post,
        "OCI cleanup requires POST"
    );
    let signature = request
        .headers()
        .get(OCI_CLEANUP_SIGNATURE_HEADER)?
        .context("OCI cleanup application signature absent")?;
    let body = crate::hybrid::read_bounded_body(request, MAX_OCI_CLEANUP_BYTES)
        .await?
        .context("OCI cleanup metadata oversized")?;
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    let work = OciCleanupRequest::authenticate(
        &key,
        &signature,
        &body,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        latest(env)?,
    )?;
    ensure!(
        work.issuer.source_digest == option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or("")
            && work.issuer.script_version
                == crate::direct_upload::config::runtime_script_version(env)?
            && work.clock_uncertainty_seconds
                == crate::direct_upload::config::integer(
                    env,
                    "HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS"
                )?
                .get(),
        "OCI cleanup guard implementation or clock differs"
    );
    Ok((work, body, signature))
}

pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        let (work, body, signature) = authenticate(&mut request, env).await?;
        let headers = Headers::new();
        headers.set(OCI_CLEANUP_SIGNATURE_HEADER, &signature)?;
        let role = super::super::storage::key(env)?;
        headers.set(
            "x-aos-oci-cleanup-guard",
            &role.sign_body(&[b"aos.oci-cleanup-physical.v1\0".as_slice(), &body].concat())?,
        )?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
        work.validate(&work.deployment_id, latest(env)?)?;
        let response = env
            .durable_object(BINDING)?
            .id_from_name(&work.scope.guard_name()?)?
            .get_stub()?
            .fetch_with_request(Request::new_with_init(
                &format!("https://guard.invalid{PHYSICAL}"),
                &init,
            )?)
            .await?;
        work.validate(&work.deployment_id, latest(env)?)?;
        ensure!(
            response.status_code() == 200,
            "OCI cleanup physical turn refused"
        );
        let signature = response
            .headers()
            .get(OCI_CLEANUP_SIGNATURE_HEADER)?
            .context("OCI cleanup guard receipt signature absent")?;
        let body = crate::hybrid::read_bounded_response(response, MAX_OCI_CLEANUP_BYTES)
            .await?
            .context("OCI cleanup guard receipt oversized")?;
        work.validate(&work.deployment_id, latest(env)?)?;
        let reply = OciCleanupReply::authenticate(&work, &role, &signature, &body)?;
        signed_response(env, &work, &reply).map_err(anyhow::Error::from)
    }
    .await;
    match result {
        Ok(response) => Ok(response),
        Err(_) => Response::error("terminal OCI cleanup refused or unknown", 409),
    }
}

fn signed_response(
    env: &Env,
    work: &OciCleanupRequest,
    reply: &OciCleanupReply,
) -> worker::Result<Response> {
    let role = super::super::storage::key(env).map_err(error)?;
    let (body, signature) = reply.sign(work, &role).map_err(error)?;
    let response = Response::from_bytes(body)?;
    response
        .headers()
        .set(OCI_CLEANUP_SIGNATURE_HEADER, &signature)?;
    response.headers().set("content-type", "application/json")?;
    response
        .headers()
        .set("cache-control", "private, no-store")?;
    Ok(response)
}

impl ExternalObjectGuard {
    pub(in crate::external_object) async fn oci_cleanup_fetch(
        &self,
        request: &mut Request,
    ) -> worker::Result<Response> {
        match self.cleanup(request).await {
            Ok((work, reply)) => signed_response(&self.env, &work, &reply),
            Err(_) => Response::error("terminal OCI chunk delete refused or unknown", 409),
        }
    }

    async fn cleanup(&self, request: &mut Request) -> Result<(OciCleanupRequest, OciCleanupReply)> {
        ensure!(
            request.url()?.path() == PHYSICAL,
            "OCI cleanup physical path differs"
        );
        let (work, body, _) = authenticate(request, &self.env).await?;
        super::super::storage::key(&self.env)?.verify_body(
            &request
                .headers()
                .get("x-aos-oci-cleanup-guard")?
                .context("OCI cleanup guard MAC absent")?,
            &[b"aos.oci-cleanup-physical.v1\0".as_slice(), &body].concat(),
        )?;
        let object = configured(&self.env)?.context("external object consumer disabled")?;
        ensure!(
            work.scope.guard_namespace_id == object.guard_namespace_id
                && self
                    .env
                    .durable_object(BINDING)?
                    .id_from_name(&work.scope.guard_name()?)?
                    .to_string()
                    == self.state.id().to_string(),
            "OCI cleanup selected another full-key guard"
        );
        let gate = loop {
            work.validate(&work.deployment_id, latest(&self.env)?)?;
            if let Some(gate) = self.gate.try_lock_owned() {
                break gate;
            }
            worker::Delay::from(Duration::from_millis(50)).await;
        };
        let storage = self.state.storage();
        let key = record_key(&work)?;
        let prior: Option<Record> = decode(storage.get::<String>(&key).await?, MAX_MESSAGE)?;
        work.validate(&work.deployment_id, latest(&self.env)?)?;
        if let Some(record) = prior {
            // The exact prior receipt is the only retry path. Pending records
            // never renew a lease, issue HEAD or redispatch DELETE.
            let reply = record.reply(&work)?;
            return Ok((work, reply));
        }
        crate::direct_guard::deny_legacy(&storage).await?;
        let head = load_head(&storage)
            .await?
            .context("OCI cleanup positive head absent")?;
        head.validate(&object, &work.scope)?;
        head.require_cleanup_ready()?;
        let visible = head
            .visible_receipt
            .as_ref()
            .context("OCI cleanup closure absent")?;
        ensure!(
            visible.kind == VisibleKind::OciStage,
            "OCI cleanup cannot delete canonical publication"
        );
        let session: Session = decode(
            storage
                .get::<String>(&super::storage::session_key(&visible.context_digest))
                .await?,
            96 * 1024,
        )?
        .context("OCI cleanup original absent")?;
        session.validate()?;
        let closed = session
            .closed
            .clone()
            .context("OCI cleanup positive chunk closure absent")?;
        super::storage::closed_for_lookup(&storage, &object, &session.original, &closed).await?;
        let publication = crate::hybrid_binding::resolve_for_delivery(
            &self.env,
            work.original.binding_id,
            work.original.binding_resource_version,
        )
        .await?;
        validate_snapshot(&work, &publication.snapshot, latest(&self.env)?)?;
        let cohort = super::super::executor::select_cohort(
            &object,
            &publication,
            "delete",
            work.original.binding_write_revision,
        )?
        .clone();
        ensure!(
            cohort.credential.generation.get() == work.original.delete_generation
                && object.scope(&cohort, work.scope.full_key.clone())? == work.scope,
            "terminal OCI Delete cohort differs from current custody"
        );
        let domains = super::super::delete_config::configured(&self.env, &object)?;
        let domain = domains.domain(&cohort)?;
        let token = super::super::stage::acquire_configured_lease(
            &self.env,
            &object,
            &domain.issuer_installation,
            &cohort,
            &cohort.admitted_prefix,
        )
        .await?;
        work.validate(&work.deployment_id, latest(&self.env)?)?;
        let nonce = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let record = Record::declare(
            &work,
            session.original,
            closed,
            digest(&cohort)?,
            nonce.clone(),
        )?;
        let (next, dispatch) = head.begin(
            &object,
            record.turn.intent.clone(),
            token.as_bytes(),
            nonce,
            object.clock(),
        )?;
        ensure!(
            matches!(dispatch, super::super::protocol::GuardReply::Dispatch { turn, .. } if turn == record.turn),
            "OCI cleanup pending turn differs"
        );
        let selected = work.clone();
        let fresh_object = object.clone();
        let snapshot = publication.snapshot.clone();
        let delete_floor = next.floor.clone();
        let fresh: Rc<dyn Fn() -> Result<()>> = Rc::new(move || {
            selected.validate(&selected.deployment_id, latest_from(&fresh_object)?)?;
            validate_snapshot(&selected, &snapshot, latest_from(&fresh_object)?)?;
            fresh_object.verifier()?.validate_lease(
                token.as_bytes(),
                &cohort,
                &fresh_object.timing_profile,
                &delete_floor,
                &selected.scope.full_key,
                LeaseEffect::ConditionalDelete,
                fresh_object.clock(),
            )?;
            Ok(())
        });
        let capacity = crate::direct_upload::provider_capacity::acquire_class_checked(
            1,
            crate::direct_upload::provider_capacity::Class::Metadata,
            &|| fresh(),
        )
        .await?;
        let owner = Owner::new((gate, capacity));
        let _scope = Scope(Rc::clone(&owner));
        fresh()?;
        let credential = publication.credential_text(
            &StorageCredentialSelector {
                purpose: "delete".into(),
                generation: work.original.delete_generation,
            },
            &work.deployment_id,
            object.clock().observed_at,
        )?;
        let surface = S3Surface::from_snapshot(
            &publication.snapshot,
            &work.deployment_id,
            &work.original.placement_prefix,
            Some(&credential),
            object.clock().observed_at,
        )?;
        let expected = record.precondition()?;
        let signed = surface.oci_conditional_read_request(
            &work.original.staging_key,
            true,
            &expected.etag,
            Some(&expected.provider_version),
            None,
            object.clock().observed_at,
        )?;
        let headers = Headers::new();
        for header in signed.required_headers {
            headers.set(&header.name, &header.value)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Head)
            .with_headers(headers)
            .with_redirect(worker::RequestRedirect::Manual);
        aos_hub_core::url_guard::is_safe_remote_url(&signed.url)?;
        let (response, _) = super::transport::fetch_owned(
            &self.state,
            Request::new_with_init(&signed.url, &init)?,
            Rc::clone(&owner),
            Rc::clone(&fresh),
        )
        .await?;
        ensure!(
            response.status_code() == 200
                && super::super::deletion::condition_matches(
                    &expected,
                    &work.original.staging_key,
                    response.headers().get("content-length")?.as_deref(),
                    response.headers().get("etag")?.as_deref(),
                    response.headers().get("x-amz-version-id")?.as_deref()
                )?,
            "OCI cleanup exact version precondition refused"
        );
        // Read refusal grants no mutation and can be retried under a fresh
        // control. The permanent unknown fence precedes only actual DELETE.
        fresh()?;
        commit(
            &storage,
            &key,
            Some(head),
            None,
            next.clone(),
            record.clone(),
        )
        .await?;
        fresh()?;
        let url = surface.versioned_conditional_delete_url(
            &work.original.staging_key,
            &expected.provider_version,
            &expected.etag,
            object.clock().observed_at,
            30,
        )?;
        aos_hub_core::url_guard::is_safe_remote_url(&url)?;
        let headers = Headers::new();
        headers.set("if-match", &expected.etag)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Delete)
            .with_headers(headers)
            .with_redirect(worker::RequestRedirect::Manual);
        let (response, _) = super::transport::fetch_owned(
            &self.state,
            Request::new_with_init(&url, &init)?,
            Rc::clone(&owner),
            Rc::clone(&fresh),
        )
        .await?;
        let outcome = super::super::deletion::acknowledgement(
            &expected,
            response.status_code(),
            response.headers().get("x-amz-version-id")?.as_deref(),
            response.headers().get("x-amz-delete-marker")?.as_deref(),
        )?;
        let receipt = Receipt {
            turn: record.turn.clone(),
            outcome,
        };
        let positive = record.acknowledge(&work, receipt.clone())?;
        let head = load_head(&storage)
            .await?
            .context("OCI cleanup pending head disappeared")?;
        head.validate(&object, &work.scope)?;
        let next = head.terminal(&receipt)?;
        commit(
            &storage,
            &key,
            Some(head),
            Some(record),
            next,
            positive.clone(),
        )
        .await?;
        work.validate(&work.deployment_id, latest(&self.env)?)?;
        Ok((work.clone(), positive.reply(&work)?))
    }
}

fn latest_from(object: &Config) -> Result<i64> {
    let clock = object.clock();
    clock
        .observed_at
        .checked_add(clock.uncertainty)
        .context("OCI cleanup clock overflow")
}

fn validate_snapshot(
    work: &OciCleanupRequest,
    snapshot: &aos_hub_core::storage_work::StorageBindingSnapshot,
    latest: i64,
) -> Result<()> {
    snapshot.validate(&work.deployment_id, latest)?;
    ensure!(
        snapshot.binding_id == work.original.binding_id
            && snapshot.binding_resource_version == work.original.binding_resource_version
            && snapshot.binding_spec_revision()? == work.original.binding_spec_revision
            && snapshot
                .credentials
                .iter()
                .any(|credential| credential.purpose == "delete"
                    && credential.generation == work.original.delete_generation)
            && work.scope.full_key
                == aos_hub_core::keymap::r2_key(
                    &snapshot.object_prefix,
                    &aos_hub_core::keymap::r2_key(
                        &work.original.placement_prefix,
                        &work.original.staging_key
                    )
                ),
        "terminal OCI cleanup current coordinates or Delete generation changed"
    );
    Ok(())
}

fn record_key(work: &OciCleanupRequest) -> Result<String> {
    Ok(format!(
        "external-oci/terminal-cleanup/v1/{}",
        work.original.fingerprint()?
    ))
}

async fn commit(
    storage: &Storage,
    key: &str,
    prior_head: Option<Head>,
    prior: Option<Record>,
    head: Head,
    record: Record,
) -> Result<()> {
    let key = key.to_owned();
    let encoded = serde_json::to_string(&record)?;
    ensure!(encoded.len() <= MAX_MESSAGE, "OCI cleanup cell oversized");
    storage
        .transaction(move |transaction| {
            let key = key.clone();
            let prior_head = prior_head.clone();
            let prior = prior.clone();
            let head = head.clone();
            let encoded = encoded.clone();
            async move {
                let current_head: Option<Head> =
                    decode(transaction_string(&transaction, HEAD).await?, MAX_MESSAGE)
                        .map_err(error)?;
                let current: Option<Record> =
                    decode(transaction_string(&transaction, &key).await?, MAX_MESSAGE)
                        .map_err(error)?;
                if current_head != prior_head || current != prior {
                    return Err(error("OCI terminal cleanup original/turn CAS refused"));
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
