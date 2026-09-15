//! Package-owned ability handler for provisioning metadata.

#[tokio::main]
async fn main() {
    if let Err(error) = aos_package::metadata::provider::run_provider_from_process().await {
        eprintln!("aos-metadata-provisioning-provider: {error:#}");
        std::process::exit(1);
    }
}
