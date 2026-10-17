//! Local TLS roots for the real live-read transport fixtures, without acceptance.

use super::RemoteStorageWorkClient;
use anyhow::{ensure, Result};

impl RemoteStorageWorkClient {
    pub(crate) fn with_live_metadata_fixture_ca(mut self, certificate: &[u8]) -> Result<Self> {
        ensure!(
            url::Url::parse(&self.endpoint)?.host_str() == Some("localhost"),
            "live metadata fixture requires the local TLS peer"
        );
        self.http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .add_root_certificate(reqwest::Certificate::from_pem(certificate)?)
            .build()?;
        Ok(self)
    }
}
