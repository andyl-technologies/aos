//! Fixed source-profile HTTP requests shared by Native and Worker adapters.
//!
//! URLs derive only from closed typed operations. Credentials and conditional
//! headers are resolved by installed effect ports after scope admission. Source
//! pagination never supplies an arbitrary next URL or changes a provider host.

use anyhow::{Context as _, Result};
use aos_assessment::security::SecurityIdentity;
use serde_json::json;
use url::Url;

use super::ProviderOperation;

/// Selects the only methods used by installed observation profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceMethod {
    /// Retrieves bounded source bytes without a request body.
    Get,
    /// Submits a bounded exact OSV batch query.
    Post,
}

/// Describes one credential-free request emitted by an installed source profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRequest {
    /// Installed profile's request method.
    pub method: SourceMethod,
    /// Fixed HTTPS source URL with safely encoded declared identities.
    pub url: Url,
    /// Exact bounded body for POST, absent for GET.
    pub body: Option<Vec<u8>>,
    /// Original OSV query positions in this response's positional order.
    pub original_positions: Vec<u32>,
}

impl ProviderOperation {
    /// Constructs bounded requests without credentials, redirects or arbitrary URLs.
    ///
    /// OSV continuations include only queries with remaining positions. NVD
    /// acquires complete product configurations across versions; the shared
    /// matcher evaluates the exact assessed version and environment locally.
    ///
    /// # Errors
    /// Returns an error for unsupported identities, invalid operation fields,
    /// excessive request bodies or malformed installed endpoint constants.
    pub fn source_requests(&self) -> Result<Vec<SourceRequest>> {
        self.validate()?;
        let mut positions = Vec::new();
        let (url, body) = match self {
            Self::ObserveReleases {
                repository, page, ..
            }
            | Self::ObserveTags {
                repository, page, ..
            } => {
                let kind = if matches!(self, Self::ObserveReleases { .. }) {
                    "releases"
                } else {
                    "tags"
                };
                let mut url = Url::parse("https://api.github.com/repos/")?;
                let (owner, project) = repository
                    .split_once('/')
                    .context("validated repository lacks owner")?;
                url.path_segments_mut()
                    .map_err(|_| anyhow::anyhow!("installed GitHub URL has no path"))?
                    .pop_if_empty()
                    .push(owner)
                    .push(project)
                    .push(kind);
                url.query_pairs_mut()
                    .append_pair("per_page", "20")
                    .append_pair("page", &page.to_string());
                (url, None)
            }
            Self::ObserveGoReleases => (
                Url::parse("https://go.dev/dl/?mode=json&include=all")?,
                None,
            ),
            Self::ObserveRepology { project } => {
                let mut url = Url::parse("https://repology.org/api/v1/project/")?;
                url.path_segments_mut()
                    .map_err(|_| anyhow::anyhow!("installed Repology URL has no path"))?
                    .pop_if_empty()
                    .push(project);
                (url, None)
            }
            Self::QueryOsv {
                queries,
                continuations,
                ..
            } => {
                let mut requests = Vec::new();
                for (index, query) in queries.iter().enumerate() {
                    let token = continuations
                        .iter()
                        .find(|continuation| continuation.position as usize == index);
                    if !continuations.is_empty() && token.is_none() {
                        continue;
                    }
                    positions.push(index as u32);
                    requests.push(
                        query.request(token.map(|continuation| continuation.token.as_str()))?,
                    );
                }
                let body = crate::validation::encoded(&json!({"queries":requests}))?;
                (Url::parse("https://api.osv.dev/v1/querybatch")?, Some(body))
            }
            Self::RetrieveAdvisories { ids, .. } => {
                return ids
                    .iter()
                    .map(|id| {
                        let mut url = Url::parse("https://api.osv.dev/v1/vulns/")?;
                        url.path_segments_mut()
                            .map_err(|_| anyhow::anyhow!("installed OSV URL has no path"))?
                            .pop_if_empty()
                            .push(id);
                        Ok(SourceRequest {
                            method: SourceMethod::Get,
                            url,
                            body: None,
                            original_positions: vec![],
                        })
                    })
                    .collect();
            }
            Self::QueryNvd {
                identity,
                start_index,
                ..
            } => {
                let SecurityIdentity::Cpe {
                    part,
                    vendor,
                    product,
                    ..
                } = identity
                else {
                    anyhow::bail!("NVD source profile requires an explicit CPE product mapping");
                };
                let mut url = nvd_url(*start_index)?;
                // A product-level query avoids turning a missing dictionary
                // entry for the current version into false negative evidence.
                let product = format!("cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*");
                url.query_pairs_mut()
                    .append_pair("virtualMatchString", &product);
                (url, None)
            }
            Self::RefreshNvd {
                modified_start,
                modified_end,
                start_index,
            } => {
                let mut url = nvd_url(*start_index)?;
                url.query_pairs_mut()
                    .append_pair("lastModStartDate", &modified_start.to_string())
                    .append_pair("lastModEndDate", &modified_end.to_string());
                (url, None)
            }
            Self::RefreshKev { .. } => (
                Url::parse(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                )?,
                None,
            ),
        };
        Ok(vec![SourceRequest {
            method: if body.is_some() {
                SourceMethod::Post
            } else {
                SourceMethod::Get
            },
            url,
            body,
            original_positions: positions,
        }])
    }
}

fn nvd_url(start_index: u32) -> Result<Url> {
    let mut url = Url::parse("https://services.nvd.nist.gov/rest/json/cves/2.0")?;
    url.query_pairs_mut()
        .append_pair("resultsPerPage", "20")
        .append_pair("startIndex", &start_index.to_string());
    Ok(url)
}
