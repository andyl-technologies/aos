//! Fresh child locking and independent memlock refusal through real retained ownership.
//!
//! The positive child must verify its own kernel mappings before readiness. The
//! negative changes only the independently authored memlock ceiling and requires
//! actual child cleanup and unchanged parent lock/root/resource authority.

use super::super::hot_fork_native::{fork_resources, native_repository, run_strict_child_flight};
use super::*;

#[test]
#[ignore = "requires isolated AOS paging VM, genuine native fork and finite memlock entitlement"]
fn production_strict_child_relocks_and_refuses_lower_kernel_entitlement() {
    let source = paging_scenario();
    environment::with_native_repository_environment(
        "strict-fork",
        58_000,
        |root, storage| native_repository(&source, root, storage),
        |config| {
            let mut config = fork_resources(config);
            config.host = config
                .host
                .with_maximum_locked_bytes(128 * 1024 * 1024)
                .expect("independent complete parent and positive child lock entitlement");
            config
        },
        |prepared, config, repository| {
            run_strict_child_flight(prepared, config, repository, source.clone());
        },
    );
    println!("STRICT_CHILD_LOCK_NATIVE_PASS");
}
