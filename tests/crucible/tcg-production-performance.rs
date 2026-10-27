// SPDX-License-Identifier: Apache-2.0
//! Measures the production Sim profile through the admitted native worker.

#[path = "tcg-managed-performance.rs"]
mod managed;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let workload = if arguments.get(1).is_some_and(|value| value == "--linux") {
        "linux"
    } else {
        "bios"
    };
    managed::run(workload, &arguments)
}
