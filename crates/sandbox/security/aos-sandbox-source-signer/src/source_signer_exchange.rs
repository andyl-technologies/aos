//! Runs the installed Source signer through its genuine selected receiving owner.
//!
//! Private credentials and the actual original remain resident for the service
//! lifecycle. Ordinary diagnostics and Root client orchestration live in Services.

use std::error::Error;
use aos_sandbox_broker::source_signer_connection::require_source_signer_process_identity_v1;

#[path = "source_signer_exchange/service/receiving.rs"]
mod receiving;

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-source-signerd.service";

/// Serves the installed Source role only through its genuine paid original.
///
/// The same fixed-image executable retains its seed, independent pin and key;
/// only accepted canonical requests lend those inputs to closed Native recipes.
/// Missing or malformed selected startup never falls back to the ordinary API.
///
/// # Errors
/// Rejects invalid fixed process arguments before startup. Once capture enters,
/// any failure terminates with the whole original and native cause still resident.
pub fn run_selected_source_signer_service_v1(
    controller_uid: u32,
    controller_gid: u32,
    signer_uid: u32,
    signer_gid: u32,
) -> Result<(), Box<dyn Error>> {
    require_source_signer_process_identity_v1(controller_uid, controller_gid, signer_uid, signer_gid)?;
    receiving::run_selected()
}
