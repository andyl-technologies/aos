//! `aos-ability-crucible` starts the optional baseline Crucible guest adapter.
//!
//! The binary is deliberately separate from the production executor. AOS test
//! profiles opt in through a protected configuration file; ordinary execution
//! has no Crucible dependency.

fn main() -> anyhow::Result<()> {
    aos_ability_crucible::run_from_args(std::env::args_os().skip(1))
}
