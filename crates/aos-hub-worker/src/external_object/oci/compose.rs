//! Bounded source-range assembly for the real completing OCI upload.
//!
//! Source guards retain their actual positive incarnations and read leases
//! through each ranged stream. One destination part buffer coalesces 64 KiB
//! views; portable source and whole-blob hashes commit only with a positive
//! part receipt. Unknown mutations never replay on a new control.

use std::rc::Rc;
use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{db::OciSha256State, storage_authority::external_object::oci::{
    OciBytes, OciObjectOriginal, OciSourceOriginal, EXTERNAL_OCI_PART_BYTES, source::*}};
use base64::Engine as _;
use md5::Digest as _;
use worker::{Env, Headers, Method, Request, RequestInit};

use super::{provider::Provider, state::{Effect, Phase, SourceCursor}, storage::Journal};
use crate::oci_projection::lifetime::{Owner, Scope};

pub(super) async fn advance<R: 'static>(env: &Env, provider: &Provider<'_>,
    journal: &mut Journal, maximum_parts: u8, owner: Rc<Owner<R>>) -> Result<()> {
    let (expected, sources) = match &journal.session.original.object {
        OciObjectOriginal::Compose { expected, sources } => (expected.clone(), sources.clone()),
        _ => anyhow::bail!("OCI materialization requires a canonical destination original"),
    };
    ensure!(journal.session.source_count == sources.count && journal.session.source_bytes == sources.bytes
        && journal.session.source_manifest_sha256.final_digest()?.encoded() == sources.sha256,
        "OCI materialization lacks its entire exact source declaration");
    if expected.size == 0 {
        super::runtime::effect(env, provider, journal, Effect::EmptyPut { bytes: expected },
            None, &[], owner).await?;
        return Ok(());
    }
    if journal.session.phase == Phase::Declared {
        super::runtime::effect(env, provider, journal, Effect::Create, None, &[], Rc::clone(&owner)).await?;
    }
    for _ in 0..maximum_parts {
        let mut cursor = journal.session.source_cursor.clone().context("OCI source continuation absent")?;
        if cursor.index == sources.count { break; }
        let mut whole = journal.session.sha256.clone();
        let mut buffer = Vec::with_capacity(EXTERNAL_OCI_PART_BYTES as usize);
        while cursor.index < sources.count && buffer.len() < EXTERNAL_OCI_PART_BYTES as usize {
            let source = journal.source(cursor.index).await?;
            provider.current()?;
            ensure!(cursor.offset < source.bytes.size, "OCI source continuation escaped its bytes");
            let length = (source.bytes.size - cursor.offset)
                .min(EXTERNAL_OCI_PART_BYTES - buffer.len() as u64);
            read_range(env, provider, &source, &mut cursor, length, &mut whole,
                &mut buffer, Rc::clone(&owner)).await?;
            if cursor.offset == source.bytes.size {
                ensure!(cursor.sha256.final_digest()?.encoded() == source.bytes.sha256,
                    "OCI complete source bytes differ from the retained SQL chunk");
                cursor.index += 1;
                cursor.offset = 0;
                cursor.sha256 = OciSha256State::initial();
            }
        }
        ensure!(!buffer.is_empty() && (buffer.len() as u64 == EXTERNAL_OCI_PART_BYTES
            || cursor.index == sources.count), "OCI materialization produced an early short part");
        let effect = Effect::Part {
            part_number: journal.session.next_part,
            bytes: OciBytes { sha256: aos_oci_types::Sha256Digest::digest(&buffer).encoded(), size: buffer.len() as u64 },
            checksum_md5: base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&buffer)),
            next_sha256: whole.clone(), next_upload_sha256: whole,
            next_source_cursor: Some(cursor),
        };
        super::runtime::effect(env, provider, journal, effect, Some(&buffer), &[], Rc::clone(&owner)).await?;
    }
    if journal.session.source_cursor.as_ref().is_some_and(|cursor| cursor.index == sources.count) {
        ensure!(journal.session.sha256.final_digest()?.encoded() == expected.sha256
            && journal.session.accepted_bytes == expected.size, "OCI full assembled blob differs from claim");
        journal.seal_source(&expected).await?;
        let parts = journal.parts().await?;
        let effect = Effect::Complete { bytes: expected,
            parts_digest: super::super::protocol::digest(&parts)? };
        super::runtime::effect(env, provider, journal, effect, None, &parts, owner).await?;
    }
    Ok(())
}

async fn read_range<R: 'static>(env: &Env, provider: &Provider<'_>, source: &OciSourceOriginal,
    cursor: &mut SourceCursor, length: u64, whole: &mut OciSha256State,
    buffer: &mut Vec<u8>, root: Rc<Owner<R>>) -> Result<()> {
    let original = &provider.work.original;
    let clock = provider.object.clock();
    let lookup = OciSourceLookup {
        version: 1, deployment_id: original.deployment_id.clone(),
        issuer: aos_hub_core::mirror_guard::MirrorGuardIssuer {
            source_digest: option_env!("AOS_HUB_WORKER_SOURCE_DIGEST").unwrap_or("").into(),
            script_version: crate::direct_upload::config::runtime_script_version(env)?,
        },
        clock_uncertainty_seconds: u64::try_from(clock.uncertainty)?, writer: original.writer.clone(),
        binding_spec_revision: original.binding_spec_revision.clone(), profile_digest: original.profile_digest.clone(),
        scope: aos_hub_core::storage_authority::control::StorageAuthorityObjectScope {
            guard_namespace_id: original.scope.guard_namespace_id.clone(),
            physical_authority_id: original.scope.physical_authority_id.clone(), full_key: source.key.clone(),
        },
        expected: source.bytes.clone(), upload_id: Some(original.upload.upload_id.clone()),
        range: Some(OciSourceRange { start: cursor.offset, length }),
        nonce: super::super::protocol::digest(&(provider.work.nonce.as_str(), cursor.index, cursor.offset, length))?,
        issued_at: clock.observed_at, expires_at: provider.work.expires_at,
    };
    let role = super::super::storage::key(env)?;
    let (body, signature) = lookup.sign(&role)?;
    let headers = Headers::new();
    headers.set(OCI_SOURCE_SIGNATURE_HEADER, &signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    provider.current()?;
    let request = Request::new_with_init(&format!("https://worker.invalid{OCI_SOURCE_PATH}"), &init)?;
    let response = provider.bounded(async {
        super::source::fetch(request, env).await.map_err(anyhow::Error::from)
    }).await?;
    let owner = Owner::new(root);
    let _scope = Scope(Rc::clone(&owner));
    // Attach cancellation before inspecting any range/receipt header.
    let reader = match response.body() {
        worker::ResponseBody::Stream(stream) => owner.attach(crate::direct_digest::Reader::new(stream.clone().into())?)?,
        _ => anyhow::bail!("OCI source range lacks a stream"),
    };
    ensure!(response.status_code() == 200, "OCI source range guard refused");
    let receipt = response.headers().get("x-aos-external-oci-source-receipt")?.context("OCI source receipt absent")?;
    ensure!(receipt.len() <= MAX_OCI_SOURCE_BYTES * 4 / 3 + 4, "OCI source range receipt oversized");
    let receipt = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(receipt)?;
    let signature = response.headers().get(OCI_SOURCE_SIGNATURE_HEADER)?.context("OCI source range MAC absent")?;
    let clock = provider.object.clock();
    let latest = clock.observed_at.checked_add(clock.uncertainty).context("OCI source clock overflow")?;
    let observed = OciSourceReply::authenticate(&lookup, &role, &signature, &receipt, latest)?;
    ensure!(observed.closed.bytes == source.bytes && observed.closed.etag == source.etag
        && observed.closed.incarnation == source.incarnation && observed.closed.receipt_digest == source.receipt_digest,
        "OCI source guard retained another original incarnation");
    let mut counted = 0_u64;
    loop {
        let (view, done) = provider.bounded(reader.read()).await?;
        counted = counted.checked_add(u64::from(view.length())).context("OCI range size overflow")?;
        ensure!(counted <= length && buffer.len().checked_add(view.length() as usize)
            .is_some_and(|size| size as u64 <= EXTERNAL_OCI_PART_BYTES), "OCI source range exceeds part admission");
        let bytes = view.to_vec();
        cursor.sha256.update(&bytes)?;
        whole.update(&bytes)?;
        buffer.extend_from_slice(&bytes);
        if done { ensure!(counted == length, "OCI source range lacks exact EOF"); break; }
    }
    cursor.offset = cursor.offset.checked_add(counted).context("OCI source offset overflow")?;
    cursor.total_bytes = cursor.total_bytes.checked_add(counted).context("OCI source total overflow")?;
    provider.current()?;
    Ok(())
}
