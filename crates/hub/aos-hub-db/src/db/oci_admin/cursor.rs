//! Opaque OCI administration keyset cursors.

use anyhow::{bail, Context, Result};
use aos_oci_types::Sha256Digest;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{OciAdminPage, OCI_ADMIN_MAX_PAGE_SIZE};
use crate::db::Database;

const CURSOR_VERSION: u8 = 1;
const CURSOR_MAX_BYTES: usize = 2_048;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CursorEnvelope {
    version: u8,
    registry_id: i64,
    selector_digest: String,
    mutation_epoch: i64,
    after_primary: String,
    after_secondary: String,
}

pub(super) struct PageContext {
    pub mutation_epoch: i64,
    pub after_primary: Option<String>,
    pub after_secondary: Option<String>,
}

pub(super) fn validate_page_size(limit: u32) -> Result<i64> {
    if limit == 0 || limit > OCI_ADMIN_MAX_PAGE_SIZE {
        bail!("OCI administration page size must be between 1 and {OCI_ADMIN_MAX_PAGE_SIZE}");
    }
    Ok(i64::from(limit) + 1)
}

pub(super) async fn page_context(
    database: &Database,
    registry_id: i64,
    selector: &str,
    cursor: Option<&str>,
) -> Result<PageContext> {
    let mutation_epoch = registry_mutation_epoch(database, registry_id).await?;
    let Some(encoded) = cursor else {
        return Ok(PageContext {
            mutation_epoch,
            after_primary: None,
            after_secondary: None,
        });
    };
    if encoded.is_empty() || encoded.len() > CURSOR_MAX_BYTES {
        bail!("OCI administration cursor has an invalid size");
    }

    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("OCI administration cursor is not canonical base64url")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        bail!("OCI administration cursor is not canonical base64url");
    }
    let envelope = serde_json::from_slice::<CursorEnvelope>(&bytes)
        .context("OCI administration cursor is malformed")?;
    if envelope.version != CURSOR_VERSION
        || envelope.registry_id != registry_id
        || envelope.selector_digest != selector_digest(selector)
        || envelope.mutation_epoch != mutation_epoch
        || envelope.after_primary.is_empty()
        || envelope.after_primary.len() > 512
        || envelope.after_secondary.len() > 512
    {
        bail!("OCI administration cursor is stale or belongs to another selector");
    }

    Ok(PageContext {
        mutation_epoch,
        after_primary: Some(envelope.after_primary),
        after_secondary: (!envelope.after_secondary.is_empty()).then_some(envelope.after_secondary),
    })
}

pub(super) fn finish_page<T>(
    mut items: Vec<T>,
    limit: u32,
    registry_id: i64,
    selector: &str,
    context: &PageContext,
    key: impl FnOnce(&T) -> (String, String),
) -> Result<OciAdminPage<T>> {
    let has_more = items.len() > limit as usize;
    if has_more {
        items.pop();
    }
    let next_cursor = if has_more {
        let last = items
            .last()
            .context("OCI administration page lost its keyset boundary")?;
        let (after_primary, after_secondary) = key(last);
        let envelope = CursorEnvelope {
            version: CURSOR_VERSION,
            registry_id,
            selector_digest: selector_digest(selector),
            mutation_epoch: context.mutation_epoch,
            after_primary,
            after_secondary,
        };
        let bytes =
            serde_json::to_vec(&envelope).context("serializing OCI administration cursor")?;
        Some(URL_SAFE_NO_PAD.encode(bytes))
    } else {
        None
    };

    Ok(OciAdminPage {
        items,
        next_cursor,
        mutation_epoch: context.mutation_epoch,
    })
}

fn selector_digest(selector: &str) -> String {
    Sha256Digest::digest(selector.as_bytes()).to_string()
}

async fn registry_mutation_epoch(database: &Database, registry_id: i64) -> Result<i64> {
    database
        .backend
        .query_opt(
            "SELECT COALESCE(state.mutation_epoch, 0)
             FROM registries registry LEFT JOIN oci_registry_state state
               ON state.registry_id = registry.id
             WHERE registry.id = ?1",
            &vals![registry_id],
        )
        .await?
        .context("OCI registry does not exist")?
        .get(0)
}
