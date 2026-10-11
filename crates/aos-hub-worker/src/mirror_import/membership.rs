//! Metadata-only membership backed by one complete verified pair catalogue.
//!
//! The cache never retains permissions or provider effects. Every read verifies
//! a fresh Native plan and current qualification; page commitments and the
//! header published last preserve full-source provenance across restarts.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::mirror_membership::{
    cache::*, MirrorMembershipProjection, MirrorMembershipQuery, MirrorObjectSummary,
};
use aos_hub_core::storage_work::{
    StorageWorkKey, StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsValue;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use crate::hybrid_object::HybridObjectGuard;

pub(crate) const PHYSICAL_PATH: &str = "/mirror-membership";
pub(crate) const CANDIDATE_PHYSICAL_PATH: &str = "/mirror-candidate-membership";
pub(crate) const HEADER: &str = "membership-cache-header";
pub(crate) const MARKER: &str = "membership-cache-marker";

fn query(plan: &StorageWorkPlan) -> Result<&MirrorMembershipQuery> {
    let StorageWorkOperation::InspectMirrorMembership { query } = &plan.operation else {
        anyhow::bail!("not a membership plan");
    };
    query.validate()?;
    Ok(query)
}

fn cache_key(plan: &StorageWorkPlan, candidate: bool) -> Result<String> {
    query(plan)?;
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| aos_hub_core::direct_upload::valid_direct_digest(source))
        .context("compiled membership source identity missing")?;
    let mut authority = plan.clone();
    authority.plan_id.clear();
    authority.issued_at = 0;
    authority.expires_at = 0;
    if let StorageWorkOperation::InspectMirrorMembership { query } = &mut authority.operation {
        query.oids.clear();
        query.expected_source = None;
    }
    let mut digest = Sha256::new();
    digest.update(b"aos-mirror-verified-catalogue-cache-v1\0");
    digest.update([u8::from(candidate)]);
    digest.update(source);
    digest.update(serde_json::to_vec(&authority)?);
    Ok(format!(
        "{}{}",
        super::inventory::CACHE_PREFIX,
        hex::encode(digest.finalize())
    ))
}

pub(crate) async fn dispatch(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
) -> Result<StorageWorkResult> {
    dispatch_inner(env, plan, body, signature, false).await
}

async fn dispatch_inner(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
    candidate: bool,
) -> Result<StorageWorkResult> {
    let key = cache_key(plan, candidate)?;
    let namespace = env.durable_object("HYBRID_OBJECT_GUARD")?;
    let stub = namespace
        .id_from_name(&crate::hybrid_object::guard_name(env, &key)?)?
        .get_stub()?;
    let headers = Headers::new();
    headers.set("x-aos-hybrid-object-key", &key)?;
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(std::str::from_utf8(body)?)));
    let path = if candidate {
        CANDIDATE_PHYSICAL_PATH
    } else {
        PHYSICAL_PATH
    };
    let request = Request::new_with_init(&format!("https://hybrid-object{path}"), &init)?;
    let mut response = stub.fetch_with_request(request).await?;
    ensure!(
        response.status_code() == 200,
        "membership cache unavailable"
    );
    let mut bytes = Vec::new();
    let mut stream = response.stream()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len() + chunk.len() <= 24 * 1024,
            "membership envelope exceeds its bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) async fn physical_fetch(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
) -> worker::Result<Response> {
    let candidate = request.url()?.path() == CANDIDATE_PHYSICAL_PATH;
    match execute(guard, key, request, candidate).await {
        Ok(result) => Response::from_json(&result),
        Err(_) => Response::error("complete verified membership unavailable", 409),
    }
}

async fn execute(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
    candidate: bool,
) -> Result<StorageWorkResult> {
    ensure!(request.method() == Method::Post, "membership requires POST");
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .context("membership signature missing")?;
    let body = crate::hybrid::read_bounded_body(request, 256 * 1024)
        .await?
        .context("membership control exceeds bound")?;
    let deployment = guard.env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let now = aos_hub_core::clock::now_unix_secs();
    let plan =
        if candidate {
            #[cfg(feature = "do-e2e")]
            {
                aos_hub_core::mirror_candidate::query::verify(
                    &super::candidate::key(&guard.env)?,
                    &signature,
                    &body,
                    &deployment,
                    now,
                )?
            }
            #[cfg(not(feature = "do-e2e"))]
            anyhow::bail!("controlled queries are absent from ordinary execution");
        } else {
            StorageWorkKey::new(guard.env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?
                .verify_plan(&signature, &body, &deployment, now)?
        };
    ensure!(
        cache_key(&plan, candidate)? == key,
        "membership authority changed"
    );
    let selected = query(&plan)?;
    let authority = if candidate {
        #[cfg(feature = "do-e2e")]
        {
            super::inspection::InventoryAuthority::controlled_query(&guard.env, &plan)?
        }
        #[cfg(not(feature = "do-e2e"))]
        anyhow::bail!("controlled query authority is unavailable");
    } else {
        super::inspection::InventoryAuthority::load(&guard.env, &plan).await?
    };
    authority.before_dispatch(&plan)?;
    let storage = guard.state.storage();
    let now = aos_hub_core::clock::now_unix_secs();
    let mut header: Option<CatalogueHeader> = storage.get(HEADER).await?;
    authority.before_dispatch(&plan)?;
    if header
        .as_ref()
        .is_some_and(|header| now >= header.expires_at)
    {
        storage.delete_all().await?;
        header = None;
    }

    let mut source_bytes = 0;
    if header.is_none() {
        storage.delete_all().await?;
        storage.put(MARKER, true).await?;
        storage
            .set_alarm(std::time::Duration::from_secs(CACHE_SECONDS as u64))
            .await?;
        authority.before_dispatch(&plan)?;
        let built = super::inspection::build_catalogue(&guard.env, &plan, &authority).await?;
        source_bytes = built.pair.pack.size + built.pair.index.size;
        let mut pages = Vec::new();
        for (index, rows) in built.objects.chunks(PAGE_OBJECTS).enumerate() {
            let commitment = page_commitment(rows)?;
            authority.within_immutable_read(&plan)?;
            storage.put(&page_key(index), rows).await?;
            pages.push(commitment);
        }
        let complete = CatalogueHeader {
            authority_digest: key.into(),
            created_at: now,
            expires_at: now
                .checked_add(CACHE_SECONDS)
                .context("membership clock overflow")?,
            pair: built.pair.clone(),
            pages,
            object_count: built.objects.len(),
        };
        complete.validate(selected, key, aos_hub_core::clock::now_unix_secs())?;
        authority.within_immutable_read(&plan)?;
        // A crashed or refused preparation leaves no authoritative header.
        storage.put(HEADER, &complete).await?;
        header = Some(complete);
        // `built` holds the sole Bulk buffer through all semantic page writes.
    }

    let header = header.context("membership cache has no complete header")?;
    let current_read = || {
        if source_bytes == 0 {
            // A hot semantic read has no long-running verification authority.
            // Preserve the exact original plan audience and 30-second cutoff
            // across buffer/storage waits and immediately before its reply.
            authority.before_dispatch(&plan)
        } else {
            // Cold reads retain only the independently bounded 600-second
            // immutable verification execution, not mutation permission.
            authority.within_immutable_read(&plan)
        }
    };
    current_read()?;
    header.validate(selected, key, aos_hub_core::clock::now_unix_secs())?;
    let indices: BTreeSet<_> = selected
        .oids
        .iter()
        .filter_map(|oid| header.page_index(oid))
        .collect();
    // Cache reads retain at most one small semantic page, even when 64 OIDs
    // span 64 pages. Two metadata admissions bound their aggregate live state
    // independently of a simultaneous full-pair Bulk verifier.
    let _buffer = super::buffers::acquire(true, &current_read).await?;
    let mut objects = vec![None; selected.oids.len()];
    for index in indices {
        let rows: Vec<MirrorObjectSummary> = storage
            .get(&page_key(index))
            .await?
            .context("membership page unavailable")?;
        current_read()?;
        let positions: Vec<_> = selected
            .oids
            .iter()
            .enumerate()
            .filter(|(_, oid)| header.page_index(oid) == Some(index))
            .map(|(position, _)| position)
            .collect();
        let mut page_query = selected.clone();
        page_query.oids = positions
            .iter()
            .map(|position| selected.oids[*position].clone())
            .collect();
        let answers = header.project(&page_query, &BTreeMap::from([(index, rows)]))?;
        for (position, answer) in positions.into_iter().zip(answers.objects) {
            objects[position] = answer;
        }
    }
    let projection = MirrorMembershipProjection {
        pair: header.pair.clone(),
        objects,
    };
    projection.validate(selected)?;
    header.validate(selected, key, aos_hub_core::clock::now_unix_secs())?;
    current_read()?;
    Ok(crate::surface::storage_work_result(
        &plan,
        StorageWorkOutcome::MirrorMembership { projection },
        source_bytes,
    ))
}

fn page_key(index: usize) -> String {
    format!("membership-page-{index:03}")
}

#[cfg(feature = "do-e2e")]
pub(crate) async fn candidate_fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    async fn run(request: &mut Request, env: &Env) -> Result<(StorageWorkResult, String)> {
        ensure!(
            request.method() == Method::Post,
            "candidate query requires POST"
        );
        let signature = request
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)?
            .context("candidate query signature missing")?;
        let body = crate::hybrid::read_bounded_body(request, 256 * 1024)
            .await?
            .context("candidate query exceeds bound")?;
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let plan = aos_hub_core::mirror_candidate::query::verify(
            &super::candidate::key(env)?,
            &signature,
            &body,
            &deployment,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        super::inspection::InventoryAuthority::controlled_query(env, &plan)?
            .before_dispatch(&plan)?;
        let key = cache_key(&plan, true)?;
        Ok((
            dispatch_inner(env, &plan, &body, &signature, true).await?,
            key,
        ))
    }
    match run(&mut request, env).await {
        Ok((result, key)) => {
            let mut response = Response::from_json(&result)?;
            response
                .headers_mut()
                .set("x-aos-controlled-membership-cache-key", &key)?;
            Ok(response)
        }
        Err(_) => Response::error("controlled complete membership unavailable", 409),
    }
}

pub(crate) async fn expire(guard: &HybridObjectGuard) -> worker::Result<Response> {
    let storage = guard.state.storage();
    let header: Option<CatalogueHeader> = storage.get(HEADER).await?;
    if let Some(header) = header {
        let remaining = header
            .expires_at
            .saturating_sub(aos_hub_core::clock::now_unix_secs());
        if remaining > 0 {
            storage
                .set_alarm(std::time::Duration::from_secs(remaining as u64))
                .await?;
            return Response::ok("membership remains within fixed lifetime");
        }
    }
    storage.delete_all().await?;
    Response::ok("membership semantic cache expired")
}
