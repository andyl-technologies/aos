//! Package-owned synchronized-registry snapshot ability handler.

fn main() {
    if let Err(error) =
        aos_package::config_eval::registry_snapshot_provider::run_provider_from_process()
    {
        eprintln!("aos-registry-snapshot-provider: {error:#}");
        std::process::exit(1);
    }
}
