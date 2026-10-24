//! Package-owned command handler for K3s Kubernetes object sets.

fn main() {
    if let Err(error) = aos_activation_kubernetes::run_from_process() {
        eprintln!("aos-kubernetes-provider: {error}");
        std::process::exit(1);
    }
}
