//! Runs the systemd platform's package-attestation quote terminal.

fn main() -> anyhow::Result<()> {
    aos_package::run_package_attestation_service()
}
