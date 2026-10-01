//! Exact-authority semantic tree pages in a bounded, expiring private cache.
//!
//! The same physical-key Durable Object authenticates each fresh Native plan.
//! Only complete verified semantic pages are cached, for a fixed 600 seconds.
//! There are no provider permissions, effect receipts or decoder checkpoints in
//! this cache. A missing continuation never fetches and reparses a source.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::mirror_tree_inventory::{
    MirrorTreeInventoryPage, MirrorTreeInventoryProjection, MirrorTreeInventoryQuery,
};
use aos_hub_core::storage_work::{
    StorageWorkKey, StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use wasm_bindgen::JsValue;
use worker::{Env, Headers, Method, Request, RequestInit, Response};

use crate::hybrid_object::HybridObjectGuard;

const CACHE_HEADER: &str = "inventory-cache-header";
const CACHE_MARKER: &str = "inventory-cache-marker";
pub(crate) const CACHE_PREFIX: &str = ".aos-mirror-query/";
pub(crate) const PHYSICAL_PATH: &str = "/mirror-tree-inventory";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheHeader {
    authority_digest: String,
    expires_at: i64,
    source: aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryCommitment,
    tree_oid: String,
    object_size: Option<u64>,
    page_count: usize,
}

fn query(plan: &StorageWorkPlan) -> Result<&MirrorTreeInventoryQuery> {
    let StorageWorkOperation::InspectMirrorTreeInventory { query } = &plan.operation else {
        anyhow::bail!("not an inventory plan");
    };
    query.validate()?;
    Ok(query)
}

fn cache_key(plan: &StorageWorkPlan) -> Result<String> {
    query(plan)?;
    let source = option_env!("AOS_HUB_WORKER_SOURCE_DIGEST")
        .filter(|source| aos_hub_core::direct_upload::valid_direct_digest(source))
        .context("compiled inventory source identity missing")?;
    let mut authority = plan.clone();
    authority.plan_id.clear();
    authority.issued_at = 0;
    authority.expires_at = 0;
    if let StorageWorkOperation::InspectMirrorTreeInventory { query } = &mut authority.operation {
        query.cursor = None;
    }
    let mut digest = Sha256::new();
    digest.update(b"aos-mirror-tree-semantic-cache-v1\0");
    digest.update(source);
    digest.update(serde_json::to_vec(&authority)?);
    Ok(format!("{CACHE_PREFIX}{}", hex::encode(digest.finalize())))
}

pub(crate) async fn dispatch(
    env: &Env,
    plan: &StorageWorkPlan,
    body: &[u8],
    signature: &str,
) -> Result<StorageWorkResult> {
    let key = cache_key(plan)?;
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
    let request = Request::new_with_init(&format!("https://hybrid-object{PHYSICAL_PATH}"), &init)?;
    let mut response = stub.fetch_with_request(request).await?;
    ensure!(
        response.status_code() == 200,
        "inventory cache refused the source or continuation"
    );

    let mut bytes = Vec::new();
    let mut stream = response.stream()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len() + chunk.len() <= 256 * 1024,
            "inventory result exceeds control bound"
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
    match execute(guard, key, request).await {
        Ok(result) => Response::from_json(&result),
        Err(_) => Response::error("inventory source or continuation unavailable", 409),
    }
}

async fn execute(
    guard: &HybridObjectGuard,
    key: &str,
    request: &mut Request,
) -> Result<StorageWorkResult> {
    ensure!(request.method() == Method::Post, "inventory requires POST");
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .context("inventory signature missing")?;
    let body = crate::hybrid::read_bounded_body(request, 256 * 1024)
        .await?
        .context("inventory control exceeds bound")?;
    let deployment = guard.env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let plan = StorageWorkKey::new(guard.env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?
        .verify_plan(
            &signature,
            &body,
            &deployment,
            aos_hub_core::clock::now_unix_secs(),
        )?;
    ensure!(cache_key(&plan)? == key, "inventory cache identity changed");
    let selected = query(&plan)?;
    let authority = super::inspection::InventoryAuthority::load(&guard.env, &plan).await?;
    authority.before_dispatch(&plan)?;
    let storage = guard.state.storage();
    let now = aos_hub_core::clock::now_unix_secs();
    let mut header: Option<CacheHeader> = storage.get(CACHE_HEADER).await?;
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
        ensure!(
            selected.cursor.is_none(),
            "expired inventory cannot renew a continuation"
        );
        // Incomplete pages are expendable semantic data. Publish the header
        // last, so a crash during any page write cannot expose a partial tree.
        storage.delete_all().await?;
        storage.put(CACHE_MARKER, true).await?;
        storage
            .set_alarm(std::time::Duration::from_secs(600))
            .await?;
        authority.before_dispatch(&plan)?;
        let Some(built) = super::inspection::build_inventory(&guard.env, &plan, &authority).await?
        else {
            authority.before_dispatch(&plan)?;
            return Ok(crate::surface::storage_work_result(
                &plan,
                StorageWorkOutcome::NotFound,
                0,
            ));
        };
        source_bytes = built.source.source_bytes();
        let expires_at = now
            .checked_add(600)
            .context("inventory cache clock overflow")?;
        ensure!(
            aos_hub_core::clock::now_unix_secs() < expires_at,
            "inventory execution expired"
        );
        for page in &built.pages {
            authority.within_immutable_read(&plan)?;
            storage.put(&page_key(page.start_index), page).await?;
        }
        let completed = CacheHeader {
            authority_digest: key.into(),
            expires_at,
            source: built.source.clone(),
            tree_oid: selected.tree_oid.clone(),
            object_size: built.object_size,
            page_count: built.pages.len(),
        };
        authority.within_immutable_read(&plan)?;
        storage.put(CACHE_HEADER, &completed).await?;
        header = Some(completed);
        // `built` retains Bulk buffer admission through every cache write.
    }

    let header = header.context("inventory cache has no complete header")?;
    let current_read = || {
        ensure!(
            aos_hub_core::clock::now_unix_secs() < header.expires_at,
            "inventory cache expired during access"
        );
        if source_bytes == 0 {
            authority.before_dispatch(&plan)
        } else {
            authority.within_immutable_read(&plan)
        }
    };
    current_read()?;
    ensure!(
        header.authority_digest == key
            && header.tree_oid == selected.tree_oid
            && aos_hub_core::clock::now_unix_secs() < header.expires_at,
        "inventory cache changed or expired"
    );
    let start = selected
        .cursor
        .as_ref()
        .map_or(0, |cursor| cursor.next_index);
    let _buffer = super::buffers::acquire(true, &current_read).await?;
    let page: Option<MirrorTreeInventoryPage> = if header.object_size.is_some() {
        ensure!(
            start / 16 < header.page_count,
            "inventory continuation exceeds cached rows"
        );
        Some(
            storage
                .get(&page_key(start))
                .await?
                .context("inventory page is incomplete")?,
        )
    } else {
        None
    };
    current_read()?;
    let projection = MirrorTreeInventoryProjection {
        source: header.source,
        tree_oid: header.tree_oid,
        object_size: header.object_size,
        page,
    };
    projection.validate(selected)?;
    current_read()?;
    Ok(crate::surface::storage_work_result(
        &plan,
        StorageWorkOutcome::MirrorTreeInventory { projection },
        source_bytes,
    ))
}

fn page_key(start: usize) -> String {
    format!("inventory-page-{start:05}")
}

pub(crate) async fn expire(guard: &HybridObjectGuard) -> worker::Result<Response> {
    let storage = guard.state.storage();
    if storage.get::<bool>(CACHE_MARKER).await? != Some(true) {
        return Response::ok("no semantic cache");
    }
    let header: Option<CacheHeader> = storage.get(CACHE_HEADER).await?;
    if let Some(header) = header {
        let remaining = header
            .expires_at
            .saturating_sub(aos_hub_core::clock::now_unix_secs());
        if remaining > 0 {
            storage
                .set_alarm(std::time::Duration::from_secs(remaining as u64))
                .await?;
            return Response::ok("semantic cache remains within fixed lifetime");
        }
    }
    storage.delete_all().await?;
    Response::ok("semantic cache expired")
}
