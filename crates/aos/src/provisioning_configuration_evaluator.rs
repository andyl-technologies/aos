//! Retained provisioning-input configuration evaluator entry point.

#[tokio::main]
async fn main() {
    if let Err(error) = aos_package::metadata::provider::run_evaluator_provider_from_process().await
    {
        eprintln!("aos-provisioning-configuration-evaluator: {error:#}");
        std::process::exit(1);
    }
}
