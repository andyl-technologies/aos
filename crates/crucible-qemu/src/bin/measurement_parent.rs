//! Runs the immutable private operator before the owned measurement VM is born.

fn main() {
    if let Err(error) = crucible_qemu::run_original_parent_operator() {
        eprintln!("{error}");
        crucible_qemu::retain_original_parent_quarantine();
    }
}
