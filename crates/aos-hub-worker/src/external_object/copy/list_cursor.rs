//! Authenticated listing continuations with an installed page ceiling.
//!
//! A cursor carries only provider pagination data, an exact listing selector
//! commitment and the next page ordinal. Every use still requires fresh SQL
//! permission, the installed List cohort and the addressed permanent floor.

use anyhow::{ensure, Result};
use aos_hub_core::{fetch::WORKER_MAX_SURFACE_LIST_CURSOR_BYTES, storage_work::StorageWorkKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"aos.external-copy-list-cursor.v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    selector: String,
    page: u32,
    provider: String,
}

/// Opens an exact continuation while enforcing the independently installed ceiling.
///
/// # Errors
/// Refuses wrong keys/selectors, noncanonical tokens, invalid ordinals or oversize.
pub(super) fn open(
    key: &StorageWorkKey,
    token: Option<&str>,
    selector: &str,
    maximum_pages: u32,
) -> Result<(u32, Option<String>)> {
    ensure!(maximum_pages > 0, "external listing page ceiling absent");
    let Some(token) = token else {
        return Ok((0, None));
    };
    ensure!(
        token.len() <= WORKER_MAX_SURFACE_LIST_CURSOR_BYTES,
        "external listing cursor exceeds public bound"
    );
    let (body, signature) = token
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("external listing cursor envelope absent"))?;
    let body = URL_SAFE_NO_PAD.decode(body)?;
    key.verify_body(signature, &[DOMAIN, &body].concat())?;
    let cursor: Cursor = serde_json::from_slice(&body)?;
    ensure!(
        serde_json::to_vec(&cursor)? == body
            && cursor.selector == selector
            && cursor.page > 0
            && cursor.page < maximum_pages
            && !cursor.provider.is_empty()
            && !cursor.provider.chars().any(char::is_control),
        "external listing continuation differs or exceeds page ceiling"
    );
    Ok((cursor.page, Some(cursor.provider)))
}

/// Seals actual provider continuation data under the same public cursor bound.
///
/// # Errors
/// Refuses a truncated result past the page ceiling, missing data or excess bytes.
pub(super) fn seal(
    key: &StorageWorkKey,
    provider: String,
    selector: &str,
    page: u32,
    maximum_pages: u32,
) -> Result<String> {
    let page = page
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("external list ordinal overflow"))?;
    ensure!(
        page < maximum_pages && !provider.is_empty() && !provider.chars().any(char::is_control),
        "external listing page ceiling exhausted"
    );
    let body = serde_json::to_vec(&Cursor {
        selector: selector.into(),
        page,
        provider,
    })?;
    let signature = key.sign_body(&[DOMAIN, &body].concat())?;
    let token = format!("{}.{signature}", URL_SAFE_NO_PAD.encode(&body));
    ensure!(
        token.len() <= WORKER_MAX_SURFACE_LIST_CURSOR_BYTES,
        "external provider continuation exceeds signed public cursor bound"
    );
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_listing_ceiling_and_selector_cannot_be_reset_by_provider_token() {
        let key = StorageWorkKey::new([8_u8; 32]).unwrap();
        let selector = "a".repeat(64);
        let first = seal(&key, "actual-provider-page-two".into(), &selector, 0, 3).unwrap();
        assert_eq!(
            open(&key, Some(&first), &selector, 3).unwrap(),
            (1, Some("actual-provider-page-two".into()))
        );
        let second = seal(&key, "actual-provider-page-three".into(), &selector, 1, 3).unwrap();
        assert_eq!(open(&key, Some(&second), &selector, 3).unwrap().0, 2);
        assert!(seal(&key, "provider-page-four".into(), &selector, 2, 3).is_err());
        assert!(open(&key, Some(&first), &"b".repeat(64), 3).is_err());
        assert!(open(
            &StorageWorkKey::new([9_u8; 32]).unwrap(),
            Some(&first),
            &selector,
            3
        )
        .is_err());
        assert!(open(&key, Some("raw-provider-cursor"), &selector, 3).is_err());
        assert!(open(&key, Some(&second), &selector, 2).is_err());
        assert!(seal(&key, "x".repeat(1024), &selector, 0, 3).is_err());
    }
}
