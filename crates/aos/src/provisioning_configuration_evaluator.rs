//! Retained provisioning-input configuration evaluator entry point.

#[tokio::main]
async fn main() {
    if let Err(error) =
        aos_package::config_eval::provisioning_evaluator_provider::run_from_process().await
    {
        eprintln!("aos-provisioning-configuration-evaluator: {error:#}");
        std::process::exit(1);
    }
}
