//! Package-owned metadata authorization and evaluation provider entry point.

#[tokio::main]
async fn main() {
    if let Err(error) = aos_metadata::policy::run_policy_provider_from_process().await {
        eprintln!("aos-metadata-policy-provider: {error:#}");
        std::process::exit(1);
    }
}
