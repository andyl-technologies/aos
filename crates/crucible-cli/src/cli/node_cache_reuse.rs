//! Explicit read-only reuse of a deterministic original observed result.
//!
//! The owning daemon authenticates installation, complete evidence closure and
//! coupled-world guarantees. This command issues no native execution nonce and
//! prints original result bytes with their verified cache key and source identity.

use clap::Subcommand;
use crucible_daemon::{
    node_control::{NodeControlRequest, NodeControlResult, request_node_control},
    node_observed_executor::NodeCacheReuseRequest,
};
use std::path::PathBuf;

use super::{CliError, bounded_file, node_error};

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(super) enum NodeCacheReuseCommand {
    /// Reuse authenticated deterministic original evidence without dispatching.
    CacheReuse {
        /// Connect to the private installed-node daemon socket.
        #[arg(long)]
        socket: PathBuf,
        /// Read the closed request with original nonce, cache key and exact inputs.
        #[arg(long)]
        request: PathBuf,
    },
}

pub(super) fn run(command: &NodeCacheReuseCommand) -> Result<(), CliError> {
    let NodeCacheReuseCommand::CacheReuse { socket, request } = command;
    let bytes = bounded_file(request, 16 * 1024 * 1024)?;
    let request = NodeCacheReuseRequest::from_json(&bytes).map_err(node_error)?;
    let request =
        NodeControlRequest::cache_reuse("operator/cache-reuse", request).map_err(node_error)?;
    let reply = request_node_control(socket, &request).map_err(node_error)?;
    let NodeControlResult::CacheReused { receipt } = reply.result else {
        return Err(node_error("daemon refused deterministic cache reuse"));
    };
    println!("{}", serde_json::to_string(&receipt).map_err(node_error)?);
    Ok(())
}
