//! Package-owned command handler for K3s Kubernetes object sets.

fn main() {
    if let Err(error) = aos_kubernetes_provider::run_from_process() {
        eprintln!("aos-kubernetes-provider: {error}");
        std::process::exit(1);
    }
}
