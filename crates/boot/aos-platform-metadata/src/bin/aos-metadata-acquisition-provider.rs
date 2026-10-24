//! Package-owned metadata acquisition provider entry point.

#[tokio::main]
async fn main() {
    if let Err(error) = aos_platform_metadata::provider::run_provider_from_process().await {
        eprintln!("aos-metadata-acquisition-provider: {error:#}");
        std::process::exit(1);
    }
}
