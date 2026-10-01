//! Qualified upstream and stored Git pair queries with bounded decoded output.
//!
//! Native signs the exact source and placement. Both source streams share an
//! atomic two-request Bulk reservation and the single graph-buffer admission.
//! Complete encoded bodies remain beside storage; only verified commitments and
//! selected decoded content cross the storage-work boundary.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::mirror_inspection::{MirrorPackProjection, MirrorPackSelection};
use aos_hub_core::storage_work::{
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
};
use aos_registry_surface::object::Oid;
use aos_registry_surface::pack_index::projection::{ContentRange, Selection};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, ResponseBody};

use crate::direct_upload::{config::QualifiedConfig, managed, provider_capacity};

pub(super) enum InventoryAuthority {
    Production {
        config: QualifiedConfig,
        accepted: super::acceptance::AcceptedMirror,
        deployment: String,
    },
    #[cfg(feature = "do-e2e")]
    ControlledQuery {
        authority: super::candidate::CandidateMirrorAuthority,
        deployment: String,
    },
}

impl InventoryAuthority {
    pub(super) async fn load(env: &Env, plan: &StorageWorkPlan) -> Result<Self> {
        let expected_profile = match &plan.operation {
            StorageWorkOperation::InspectMirrorTreeInventory { query } => {
                query.validate()?;
                query.source.profile_digest()
            }
            StorageWorkOperation::InspectMirrorMembership { query } => {
                query.validate()?;
                &query.inspection.protected_profile_digest
            }
            _ => anyhow::bail!("not a semantic cache plan"),
        };
        let config = QualifiedConfig::load(env).await?;
        let (profile, _) = config.managed(env)?;
        ensure!(
            profile.digest()? == expected_profile,
            "inventory profile changed"
        );
        let accepted = super::acceptance::require_pack_inspection(
            env,
            &profile,
            &config.acceptance_evidence,
            8 * 1024 * 1024,
        )
        .await?;
        Ok(Self::Production {
            config,
            accepted,
            deployment: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        })
    }

    pub(super) fn current(&self) -> Result<()> {
        match self {
            Self::Production {
                config, accepted, ..
            } => accepted.check(config.latest_now()?),
            #[cfg(feature = "do-e2e")]
            Self::ControlledQuery { authority, .. } => authority.latest_now().map(|_| ()),
        }
    }

    pub(super) fn before_dispatch(&self, plan: &StorageWorkPlan) -> Result<()> {
        let (deployment, latest) = match self {
            Self::Production {
                config,
                accepted,
                deployment,
            } => {
                let latest = config.latest_now()?;
                accepted.check(latest)?;
                (deployment, latest)
            }
            #[cfg(feature = "do-e2e")]
            Self::ControlledQuery {
                authority,
                deployment,
            } => (deployment, authority.latest_now()?),
        };
        plan.validate(deployment, i64::try_from(latest)?)?;
        Ok(())
    }

    pub(super) fn within_immutable_read(&self, plan: &StorageWorkPlan) -> Result<()> {
        self.current()?;
        let latest = match self {
            Self::Production { config, .. } => config.latest_now()?,
            #[cfg(feature = "do-e2e")]
            Self::ControlledQuery { authority, .. } => authority.latest_now()?,
        };
        let issued = u64::try_from(plan.issued_at)?;
        let cutoff = issued
            .checked_add(600)
            .context("immutable read cutoff overflow")?;
        ensure!(
            latest >= issued && latest < cutoff,
            "immutable read execution expired"
        );
        Ok(())
    }

    #[cfg(feature = "do-e2e")]
    pub(super) fn controlled_query(env: &Env, plan: &StorageWorkPlan) -> Result<Self> {
        let StorageWorkOperation::InspectMirrorMembership { query } = &plan.operation else {
            anyhow::bail!("candidate authority requires a closed membership query");
        };
        query.validate()?;
        Ok(Self::ControlledQuery {
            authority: super::candidate::load_profile(
                env,
                &query.inspection.protected_profile_digest,
            )?,
            deployment: env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        })
    }
}

pub(super) struct CatalogueBuild {
    pub(super) pair: MirrorPackProjection,
    pub(super) objects: Vec<aos_hub_core::mirror_membership::MirrorObjectSummary>,
    _buffer: super::buffers::Permit,
}

pub(super) async fn build_catalogue(
    env: &Env,
    plan: &StorageWorkPlan,
    authority: &InventoryAuthority,
) -> Result<CatalogueBuild> {
    let StorageWorkOperation::InspectMirrorMembership { query } = &plan.operation else {
        anyhow::bail!("not a membership plan");
    };
    let before_dispatch = || authority.before_dispatch(plan);
    let buffer = super::buffers::acquire(false, &before_dispatch).await?;
    let capacity = provider_capacity::acquire_class_checked(
        2,
        provider_capacity::Class::Bulk,
        &before_dispatch,
    )
    .await?;
    let index_path = &query.inspection.index_path;
    let pack_path = aos_registry_surface::pack_index::companion_pack_path(index_path)
        .context("catalogue index is not canonical")?;
    let upstream = Some(query.inspection.upstream_base.as_str());
    let pack = open_source(
        env,
        plan,
        upstream,
        &pack_path,
        8 * 1024 * 1024,
        &capacity,
        &before_dispatch,
    )
    .await?;
    let index = open_source(
        env,
        plan,
        upstream,
        index_path,
        4 * 1024 * 1024,
        &capacity,
        &before_dispatch,
    )
    .await?;
    let deadline = plan
        .issued_at
        .checked_add(600)
        .context("catalogue execution clock overflow")?;
    let verified = super::pack::verify_catalogue(
        index_path,
        pack.stream.clone(),
        index.stream.clone(),
        deadline,
        || authority.within_immutable_read(plan),
    )
    .await?;
    ensure!(
        verified.pair.pack.size == pack.size && verified.pair.index.size == index.size,
        "catalogue source length changed"
    );
    let pair =
        MirrorPackProjection::from_verified(verified.pair, pack.etag.clone(), index.etag.clone())?;
    let objects = verified
        .objects
        .into_iter()
        .map(
            |object| aos_hub_core::mirror_membership::MirrorObjectSummary {
                oid: object.oid.to_hex(),
                kind: object.kind.as_str().into(),
                object_size: object.object_size,
            },
        )
        .collect::<Vec<_>>();
    ensure!(
        serde_json::to_vec(&objects)?.len() <= aos_hub_core::mirror_membership::MAX_CATALOGUE_BYTES,
        "complete catalogue exceeds semantic cache bound"
    );
    authority.within_immutable_read(plan)?;
    Ok(CatalogueBuild {
        pair,
        objects,
        _buffer: buffer,
    })
}

pub(super) struct InventoryBuild {
    pub(super) source: aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryCommitment,
    pub(super) object_size: Option<u64>,
    pub(super) pages: Vec<aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryPage>,
    // Admission remains held while the caller serializes and stores all pages.
    _buffer: super::buffers::Permit,
}

pub(super) async fn build_inventory(
    env: &Env,
    plan: &StorageWorkPlan,
    authority: &InventoryAuthority,
) -> Result<Option<InventoryBuild>> {
    let StorageWorkOperation::InspectMirrorTreeInventory { query } = &plan.operation else {
        anyhow::bail!("not an inventory plan");
    };
    let before_dispatch = || authority.before_dispatch(plan);
    let buffer = super::buffers::acquire(false, &before_dispatch).await?;
    let capacity = provider_capacity::acquire_class_checked(
        2,
        provider_capacity::Class::Bulk,
        &before_dispatch,
    )
    .await?;
    let aos_hub_core::mirror_tree_inventory::MirrorTreeInventorySource::Pack { inspection } =
        &query.source
    else {
        return build_loose_inventory(env, plan, authority, query, buffer, &capacity).await;
    };
    let index_path = &inspection.index_path;
    let pack_path = aos_registry_surface::pack_index::companion_pack_path(index_path)
        .context("inventory index is not canonical")?;
    let upstream = Some(query.source.upstream_base());
    let pack = open_source(
        env,
        plan,
        upstream,
        &pack_path,
        8 * 1024 * 1024,
        &capacity,
        &before_dispatch,
    )
    .await?;
    let index = open_source(
        env,
        plan,
        upstream,
        index_path,
        4 * 1024 * 1024,
        &capacity,
        &before_dispatch,
    )
    .await?;
    let deadline = plan
        .issued_at
        .checked_add(600)
        .context("inventory execution clock overflow")?;
    let verified = super::pack::verify_tree(
        index_path,
        Oid::from_hex(&query.tree_oid)?,
        pack.stream.clone(),
        index.stream.clone(),
        deadline,
        || authority.within_immutable_read(plan),
        |tree| {
            aos_hub_core::mirror_tree_inventory::project_pages(
                &query.tree_oid,
                tree,
                &"0".repeat(64),
            )
        },
    )
    .await?;
    ensure!(
        verified.pair.pack.size == pack.size && verified.pair.index.size == index.size,
        "inventory pair source length changed"
    );
    let pair =
        MirrorPackProjection::from_verified(verified.pair, pack.etag.clone(), index.etag.clone())?;
    let source = pair.source_commitment()?;
    let (object_size, mut pages) = match verified.tree {
        Some(tree) => (Some(tree.object_size), tree.projection),
        None => (None, Vec::new()),
    };
    for page in &mut pages {
        page.source_commitment = source.clone();
        if let Some(cursor) = &mut page.next_cursor {
            cursor.source_commitment = source.clone();
        }
    }
    authority.within_immutable_read(plan)?;
    Ok(Some(InventoryBuild {
        source: aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryCommitment::Pack { pair },
        object_size,
        pages,
        _buffer: buffer,
    }))
}

async fn build_loose_inventory(
    env: &Env,
    plan: &StorageWorkPlan,
    authority: &InventoryAuthority,
    query: &aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryQuery,
    buffer: super::buffers::Permit,
    _capacity: &provider_capacity::Permit,
) -> Result<Option<InventoryBuild>> {
    use aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryCommitment;
    use aos_registry_surface::object::{self, ObjectKind};
    use sha2::{Digest as _, Sha256};

    let path = Oid::from_hex(&query.tree_oid)?.loose_path();
    let base = url::Url::parse(&format!(
        "{}/",
        query.source.upstream_base().trim_end_matches('/')
    ))?;
    let url = base.join(&path)?;
    ensure!(
        url.origin() == base.origin() && url.path().starts_with(base.path()),
        "loose tree escaped approved origin/path"
    );
    aos_hub_core::url_guard::is_safe_remote_url(url.as_str())?;
    let headers = Headers::new();
    headers.set("accept-encoding", "identity")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(url.as_str(), &init)?;
    authority.before_dispatch(plan)?;
    provider_capacity::record_dispatch();
    let response = Fetch::Request(request).send().await?;
    authority.before_dispatch(plan)?;
    if response.status_code() == 404 {
        return Ok(None);
    }
    ensure!(
        response.status_code() == 200,
        "loose tree source refused or redirected"
    );
    let size: u64 = response
        .headers()
        .get("content-length")?
        .context("loose tree source omitted length")?
        .parse()?;
    ensure!(
        size <= 8 * 1024 * 1024,
        "loose tree encoded source exceeds bound"
    );
    let etag = response
        .headers()
        .get("etag")?
        .context("loose tree source omitted incarnation")?;
    aos_hub_core::surface_write::strong_if_match_etag(&etag)?;
    let (_, body) = response.into_parts();
    let ResponseBody::Stream(stream) = body else {
        anyhow::bail!("loose tree requires native source stream");
    };
    let source = Source { stream, etag, size };
    let reader = crate::direct_digest::Reader::new(source.stream.clone().into())?;
    let deadline = plan
        .issued_at
        .checked_add(600)
        .context("loose tree execution overflow")?;
    let mut encoded = Vec::new();
    loop {
        let (view, done) =
            super::pack::read_checked(&reader, deadline, &|| authority.within_immutable_read(plan))
                .await?;
        ensure!(
            encoded.len() as u64 + u64::from(view.length()) <= size,
            "loose source exceeded exact length"
        );
        encoded.extend_from_slice(&view.to_vec());
        if done {
            break;
        }
    }
    ensure!(
        encoded.len() as u64 == size,
        "loose source ended before exact length"
    );
    let object = aos_hub_core::mirror_inspection::MirrorPackSource {
        path,
        sha256: hex::encode(Sha256::digest(&encoded)),
        size,
        etag: source.etag.clone(),
    };
    let (kind, content) = object::decode_loose_with_limit(
        &encoded,
        Some(Oid::from_hex(&query.tree_oid)?),
        4 * 1024 * 1024 + 64,
    )?;
    ensure!(
        kind == ObjectKind::Tree && content.len() <= 4 * 1024 * 1024,
        "loose inventory is not a bounded tree"
    );
    drop(encoded);
    let commitment = MirrorTreeInventoryCommitment::Loose { object };
    let pages = aos_hub_core::mirror_tree_inventory::project_pages(
        &query.tree_oid,
        &content,
        &commitment.source_commitment()?,
    )?;
    authority.within_immutable_read(plan)?;
    Ok(Some(InventoryBuild {
        source: commitment,
        object_size: Some(content.len() as u64),
        pages,
        _buffer: buffer,
    }))
}

pub(crate) async fn execute(env: &Env, plan: &StorageWorkPlan) -> Result<StorageWorkResult> {
    let (index_path, selections, profile_digest, upstream): (
        &str,
        &[MirrorPackSelection],
        &str,
        Option<&str>,
    ) = match &plan.operation {
        StorageWorkOperation::FilterStoredGitPackTree { query } => {
            query.validate()?;
            (
                &query.index_path,
                &[],
                &query.protected_profile_digest,
                None,
            )
        }
        StorageWorkOperation::InspectMirrorPack { inspection } => {
            inspection.validate()?;
            (
                &inspection.index_path,
                &inspection.selections,
                &inspection.protected_profile_digest,
                Some(inspection.upstream_base.as_str()),
            )
        }
        StorageWorkOperation::InspectStoredGitPack {
            index_path,
            selections,
            protected_profile_digest,
        } => (index_path, selections, protected_profile_digest, None),
        _ => anyhow::bail!("not a pack inspection plan"),
    };
    let config = QualifiedConfig::load(env).await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let (profile, _) = config.managed(env)?;
    ensure!(
        profile.digest()? == *profile_digest,
        "pack inspection profile changed"
    );
    let accepted = super::acceptance::require_pack_inspection(
        env,
        &profile,
        &config.acceptance_evidence,
        8 * 1024 * 1024,
    )
    .await?;
    let current = || -> Result<()> { accepted.check(config.latest_now()?) };
    let before_dispatch = || -> Result<()> {
        current()?;
        plan.validate(&deployment, i64::try_from(config.latest_now()?)?)?;
        Ok(())
    };
    let _buffer = super::buffers::acquire(false, &before_dispatch).await?;
    let capacity = provider_capacity::acquire_class_checked(
        2,
        provider_capacity::Class::Bulk,
        &before_dispatch,
    )
    .await?;
    let pack_path = aos_registry_surface::pack_index::companion_pack_path(index_path)
        .context("pack inspection index path is not canonical")?;
    let pack = open_source(
        env,
        plan,
        upstream,
        &pack_path,
        8 * 1024 * 1024,
        &capacity,
        &before_dispatch,
    )
    .await?;
    let index = open_source(
        env,
        plan,
        upstream,
        index_path,
        4 * 1024 * 1024,
        &capacity,
        &before_dispatch,
    )
    .await?;
    let selected = selections
        .iter()
        .map(selection)
        .collect::<Result<Vec<_>>>()?;
    let deadline = plan
        .issued_at
        .checked_add(600)
        .context("pack execution clock overflow")?;
    if let StorageWorkOperation::FilterStoredGitPackTree { query } = &plan.operation {
        // The callback emits rows before the verifier returns its source
        // commitments. Bind its local placeholder only after full verification;
        // no placeholder or raw tree is ever returned to Native.
        let placeholder = "0".repeat(64);
        let mut local_cursor = query.cursor.clone();
        if let Some(cursor) = &mut local_cursor {
            cursor.source_commitment = placeholder.clone();
        }
        let verified = super::pack::verify_tree(
            index_path,
            Oid::from_hex(&query.oid)?,
            pack.stream.clone(),
            index.stream.clone(),
            deadline,
            &current,
            |tree| {
                aos_hub_core::tree_projection::project_tree(
                    &query.oid,
                    tree,
                    &query.names,
                    local_cursor.as_ref(),
                    &placeholder,
                )
            },
        )
        .await?;
        ensure!(
            verified.pair.pack.size == pack.size && verified.pair.index.size == index.size,
            "pack tree source length changed"
        );
        let pair = MirrorPackProjection::from_verified(
            verified.pair,
            pack.etag.clone(),
            index.etag.clone(),
        )?;
        let source = pair.source_commitment()?;
        let (object_size, page) = match verified.tree {
            Some(tree) => {
                let mut page = tree.projection;
                page.source_commitment = source.clone();
                if let Some(cursor) = &mut page.next_cursor {
                    cursor.source_commitment = source;
                }
                (Some(tree.object_size), Some(page))
            }
            None => (None, None),
        };
        let projection = aos_hub_core::mirror_inspection::MirrorPackTreeProjection {
            pair,
            tree_oid: query.oid.clone(),
            object_size,
            page,
        };
        projection.validate(query)?;
        current()?;
        let source_bytes = projection.pair.pack.size + projection.pair.index.size;
        return Ok(crate::surface::storage_work_result(
            plan,
            StorageWorkOutcome::GitPackTreeProjection { projection },
            source_bytes,
        ));
    }
    let verified = super::pack::verify_pair(
        index_path,
        &selected,
        pack.stream.clone(),
        index.stream.clone(),
        deadline,
        &current,
    )
    .await?;
    ensure!(
        verified.pair.pack.size == pack.size && verified.pair.index.size == index.size,
        "pack inspection source length changed"
    );
    let source_bytes = verified
        .pair
        .pack
        .size
        .checked_add(verified.pair.index.size)
        .context("pack inspection source byte count overflow")?;
    let projection =
        MirrorPackProjection::from_available(verified, pack.etag.clone(), index.etag.clone())?;
    projection.validate(index_path, selections)?;
    current()?;
    Ok(crate::surface::storage_work_result(
        plan,
        StorageWorkOutcome::GitPackProjection { projection },
        source_bytes,
    ))
}

fn selection(selection: &MirrorPackSelection) -> Result<Selection> {
    Ok(Selection {
        oid: Oid::from_hex(&selection.oid)?,
        range: selection.range.map(|range| ContentRange {
            start: range.start,
            end: range.end,
        }),
    })
}

struct Source {
    stream: worker::web_sys::ReadableStream,
    etag: String,
    size: u64,
}

impl Drop for Source {
    fn drop(&mut self) {
        // Cancellation also covers a failed second GET or verifier setup. A
        // fully consumed stream is harmless to cancel again.
        let cancellation = self.stream.cancel();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = wasm_bindgen_futures::JsFuture::from(cancellation).await;
        });
    }
}

async fn open_source(
    env: &Env,
    plan: &StorageWorkPlan,
    upstream: Option<&str>,
    path: &str,
    maximum: u64,
    capacity: &provider_capacity::Permit,
    before_dispatch: &impl Fn() -> Result<()>,
) -> Result<Source> {
    before_dispatch()?;
    let source = if let Some(upstream) = upstream {
        let base = url::Url::parse(&format!("{}/", upstream.trim_end_matches('/')))?;
        let url = base.join(path)?;
        ensure!(
            url.origin() == base.origin() && url.path().starts_with(base.path()),
            "pack source escaped approved origin/path"
        );
        aos_hub_core::url_guard::is_safe_remote_url(url.as_str())?;
        let headers = Headers::new();
        headers.set("accept-encoding", "identity")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Get)
            .with_headers(headers)
            .with_redirect(RequestRedirect::Manual);
        let request = Request::new_with_init(url.as_str(), &init)?;
        before_dispatch()?;
        provider_capacity::record_dispatch();
        let response = Fetch::Request(request).send().await?;
        ensure!(
            response.status_code() == 200,
            "pack source refused or redirected"
        );
        let size = response
            .headers()
            .get("content-length")?
            .context("pack source has no exact length")?
            .parse::<u64>()?;
        let etag = response
            .headers()
            .get("etag")?
            .context("pack source has no strong ETag")?;
        let (_, body) = response.into_parts();
        let ResponseBody::Stream(stream) = body else {
            anyhow::bail!("pack inspection requires a native source stream");
        };
        Source { stream, etag, size }
    } else {
        let key = plan.object_key(path)?;
        let (receipt, stream) = managed::get_reserved(env, &key, capacity).await?;
        Source {
            stream,
            etag: receipt.etag,
            size: receipt.byte_size.get(),
        }
    };
    ensure!(
        source.size <= maximum,
        "pack source exceeds its accepted format bound"
    );
    aos_hub_core::surface_write::strong_if_match_etag(&source.etag)?;
    before_dispatch()?;
    Ok(source)
}
