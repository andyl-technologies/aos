//! Package-owned metadata authorization and evaluation provider entry point.

#[tokio::main]
async fn main() {
    if let Err(error) = aos_package::metadata::provider::run_provider_from_process().await {
        eprintln!("aos-metadata-policy-provider: {error:#}");
        std::process::exit(1);
    }
}
