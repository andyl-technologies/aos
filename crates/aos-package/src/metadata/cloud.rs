//! Cloud-vendor [`PlatformFetcher`] stubs.
//!
//! AWS IMDSv2 ([`crate::metadata::aws`]) is the implemented exemplar. GCP,
//! Azure, DigitalOcean, and OpenStack-IMDS follow the identical shape — a
//! different base URL, a mandatory header, and a payload encoding — but are
//! left as explicit `TODO` stubs until each has a recorded-fixture test and a
//! native-path fleet gate (provisioning.md Phase C). Each stub returns
//! `Ok(None)` / `Facts::default()` so an un-ported platform is **failure-safe**:
//! it falls through to the Ignition-compat path, never wedging boot.
//!
//! Each stub documents its documented contract so the port is a fill-in:
//!
//! | Platform | user-data path | required header | encoding |
//! |---|---|---|---|
//! | GCP | `…/attributes/user-data` | `Metadata-Flavor: Google` | plain |
//! | Azure | IMDS `/metadata/instance/compute/userData` (+ OVF `CustomData`) | `Metadata: true` | base64 |
//! | DigitalOcean | `/metadata/v1/user-data` | none | plain |
//! | OpenStack-IMDS | `/openstack/latest/user_data` | none | plain |

use anyhow::Result;

use super::fetcher::{Facts, PlatformFetcher, UserData};
use super::http::MetadataHttp;

/// Declare a stub fetcher with the given struct name and `platform_id`.
macro_rules! stub_fetcher {
    ($(#[$meta:meta])* $name:ident, $id:literal) => {
        $(#[$meta])*
        #[derive(Default)]
        pub struct $name;

        #[async_trait::async_trait]
        impl PlatformFetcher for $name {
            fn platform_id(&self) -> &'static str {
                $id
            }

            async fn fetch_user_data(&self, _http: &dyn MetadataHttp) -> Result<Option<UserData>> {
                // TODO: implement the documented contract for
                // this platform with a recorded-fixture test, mirroring
                // `crate::metadata::aws::AwsImdsFetcher`. Until then, no
                // user-data ⇒ gen-0-only / Ignition-compat fallback.
                Ok(None)
            }

            async fn fetch_facts(&self, _http: &dyn MetadataHttp) -> Result<Facts> {
                // TODO: fetch the platform's metadata document.
                Ok(Facts::default())
            }
        }
    };
}

stub_fetcher!(
    /// GCP metadata server. Base `http://metadata.google.internal`, header
    /// `Metadata-Flavor: Google` mandatory on every request; user-data at
    /// `computeMetadata/v1/instance/attributes/user-data`.
    GcpFetcher,
    "gcp"
);

stub_fetcher!(
    /// Azure IMDS + OVF. IMDS base `http://169.254.169.254`, header
    /// `Metadata: true`, `api-version` query param mandatory; `userData` is
    /// base64. The OVF `CustomData` ISO channel is the dual delivery path.
    AzureFetcher,
    "azure"
);

stub_fetcher!(
    /// DigitalOcean IMDS. Base `http://169.254.169.254`, no header; user-data
    /// at `/metadata/v1/user-data`; static IPs delivered via
    /// `/metadata/v1/interfaces/public/0/{ipv4,anchor_ipv4}`.
    DigitalOceanFetcher,
    "digitalocean"
);

stub_fetcher!(
    /// OpenStack IMDS (the network-served sibling of the `config-2` drive).
    /// Base `http://169.254.169.254`, user-data at `/openstack/latest/user_data`,
    /// network at `/openstack/latest/network_data.json`.
    OpenStackImdsFetcher,
    "openstack"
);
