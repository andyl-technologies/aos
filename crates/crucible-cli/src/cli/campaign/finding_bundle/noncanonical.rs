//! Branch-local GDB register mutation from an authenticated finding bundle.
//!
//! The original and branch restorations share immutable checkpoint bytes but
//! own separate QEMU runs. A write is reported only after the branch relay
//! acknowledges it, branch readback matches, and the original readback stays
//! unchanged.

use std::fmt::Write as _;
use std::time::Duration;

use crucible_api::{DebugControllerAccess, DebugRelayId, SessionRef};
use serde_json::json;

use super::*;

/// Proves a register edit on a second private QEMU restoration of one bundle.
///
/// # Errors
///
/// Returns an error for unauthenticated bundle material, failed independent
/// restores, a rejected or unverified GDB write, or changed canonical state.
pub(crate) fn run_finding_bundle_fork_write(
    cli: &Cli,
    args: &CampaignFindingBundleForkWriteArgs,
) -> Result<(), CliError> {
    let midpoint_args = &args.midpoint;
    if midpoint_args.node.is_empty() || args.xor_mask == 0 {
        return Err(usage_error(
            "fork write requires a nonempty node and nonzero mask",
        ));
    }

    let prepared = midpoint::prepare_finding_bundle_midpoint(cli, midpoint_args)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let _private_guard = prepared.private;
        let transport = midpoint::private_midpoint_transport(_private_guard.path())?;
        let checkpoint_id = prepared.midpoint.checkpoint();
        let checkpoint_identity = prepared.midpoint.loaded_checkpoint().production_identity();
        let verify_checkpoints = Arc::clone(&prepared.checkpoints);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(CliError::Io)?;
        let address = listener.local_addr().map_err(CliError::Io)?;
        let role = DebugRole::new([
            DebugCapability::Observe,
            DebugCapability::Control,
            DebugCapability::Mutate,
            DebugCapability::Shell,
        ]);
        let mut policy = DebugAuthorizationPolicy::deny_all();
        policy
            .grant_certificate_role(transport.client_identity.certificate_sha256(), role.clone())
            .map_err(|error| backend_error(format!("fork client role is invalid: {error}")))?;
        let client = RpcControlClient::new_mtls(
            RpcEndpoint::http2(format!("https://{address}")),
            RpcMutualTlsConfig::from_pem(transport.ca_pem, transport.client_identity_pem),
        )
        .map_err(control_client_error)?;
        let sessions = prepared
            .midpoint
            .admit_guarded_debug_session_pair(
                prepared.checkpoints,
                prepared.lifecycle,
                prepared.host,
                prepared.resources,
            )
            .await
            .map_err(|error| {
                backend_error(format!("finding midpoint pair restore failed: {error}"))
            })?;
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve_shared_lifecycle_http2_mtls_with_mode_until_shutdown(
            listener,
            sessions.shared_control_plane(),
            LifecycleServerMode::read_write(),
            transport.acceptor,
            policy,
            async move {
                let _ = stopped.await;
            },
        ));
        let result = async {
            if sessions.canonical() == sessions.branch() {
                return Err(backend_error(
                    "finding midpoint pair reused one session identity",
                ));
            }
            let proof =
                prove_register_write(&client, &sessions, &role, midpoint_args, args).await?;
            let after = load_authenticated_bundle(&midpoint_args.input)?;
            if prepared.report["archive_manifest"] != json!(after.archive_id.to_string()) {
                return Err(backend_error(
                    "finding bundle changed after private debug write",
                ));
            }
            let reloaded = verify_checkpoints
                .load_attempt_checkpoint(checkpoint_id)
                .map_err(|error| backend_error(format!("finding checkpoint changed: {error}")))?;
            if reloaded.production_identity() != checkpoint_identity {
                return Err(backend_error(
                    "finding checkpoint identity changed after debug write",
                ));
            }

            let mut report = prepared.report;
            report["schema"] = json!("crucible.cli.campaign-finding-bundle-fork-write.v1");
            report["operation"] = json!("fork-finding-bundle-midpoint-register-write");
            report["branch_classification"] = json!("non-canonical");
            report["read_only"] = json!(false);
            report["canonical_session_unchanged"] = json!(true);
            report["checkpoint_unchanged"] = json!(true);
            report["archive_manifest_unchanged"] = json!(true);
            report["register"] = json!(args.register);
            report["canonical_register_hex"] = json!(lower_hex(&proof.before));
            report["branch_register_hex"] = json!(lower_hex(&proof.after));
            report["branch"] = json!(proof.branch_id);
            midpoint::print_midpoint_report(&report, cli.output_format())?;
            if args.serve {
                crate::cli_triage_debug::run_private_unix_debug_relay_with_client_async(
                    &client,
                    sessions.branch(),
                    crucible::NodeId {
                        name: midpoint_args.node.clone(),
                    },
                    &_private_guard.path().join("gdb.sock"),
                )
                .await?;
            }
            Ok::<_, CliError>(())
        }
        .await;
        let lifecycle_client = sessions.in_process_client();
        let destroyed_branch = lifecycle_client
            .destroy_session(
                DestroySessionRequest::new(sessions.branch())
                    .with_expected_epoch(sessions.branch().epoch),
            )
            .await
            .map_err(control_client_error);
        let destroyed_canonical = lifecycle_client
            .destroy_session(
                DestroySessionRequest::new(sessions.canonical())
                    .with_expected_epoch(sessions.canonical().epoch),
            )
            .await
            .map_err(control_client_error);
        drop(client);
        let _ = shutdown.send(());
        let served = match tokio::time::timeout(Duration::from_secs(10), &mut server).await {
            Ok(result) => result
                .map_err(|error| backend_error(format!("finding fork relay task failed: {error}")))
                .and_then(|served| served.map_err(CliError::Io)),
            Err(_) => {
                server.abort();
                let _ = server.await;
                Err(backend_error("finding fork relay shutdown timed out"))
            }
        };
        let mut teardown_errors = Vec::new();
        if let Err(error) = destroyed_branch {
            teardown_errors.push(format!("branch destroy: {error}"));
        }
        if let Err(error) = destroyed_canonical {
            teardown_errors.push(format!("canonical destroy: {error}"));
        }
        if let Err(error) = served {
            teardown_errors.push(format!("relay shutdown: {error}"));
        }
        if teardown_errors.is_empty() {
            return result;
        }
        let teardown = teardown_errors.join("; ");
        match result {
            Ok(()) => Err(backend_error(format!(
                "finding fork teardown failed: {teardown}"
            ))),
            Err(error) => Err(backend_error(format!(
                "{error}; finding fork teardown failed: {teardown}"
            ))),
        }
    })
}

struct RegisterWriteProof {
    branch_id: String,
    before: Vec<u8>,
    after: Vec<u8>,
}

async fn prove_register_write(
    client: &RpcControlClient,
    sessions: &crucible_daemon::ArchivedFindingDebugSessionPair,
    role: &DebugRole,
    midpoint: &CampaignFindingBundleMidpointArgs,
    args: &CampaignFindingBundleForkWriteArgs,
) -> Result<RegisterWriteProof, CliError> {
    let node = crucible::NodeId {
        name: midpoint.node.clone(),
    };
    let canonical = sessions.canonical();
    let branch = sessions.branch();
    let canonical_access = client
        .acquire_debug_controller(canonical, &crucible_api::DebugControllerAcquisition::new())
        .await
        .map_err(control_client_error)?;
    let branch_access = client
        .acquire_debug_controller(branch, &crucible_api::DebugControllerAcquisition::new())
        .await
        .map_err(control_client_error)?;
    client
        .attach_debugger(canonical, &canonical_access, &node)
        .await
        .map_err(control_client_error)?;
    client
        .attach_debugger(branch, &branch_access, &node)
        .await
        .map_err(control_client_error)?;
    let canonical_relay = client
        .open_debug_relay(canonical, &canonical_access)
        .await
        .map_err(control_client_error)?;
    let branch_relay = client
        .open_debug_relay(branch, &branch_access)
        .await
        .map_err(control_client_error)?;

    let register = format!("p{:x}", args.register);
    let canonical_before = read_register(
        client,
        canonical,
        &canonical_access,
        canonical_relay,
        &register,
    )
    .await?;
    let branch_before =
        read_register(client, branch, &branch_access, branch_relay, &register).await?;
    if canonical_before != branch_before {
        return Err(backend_error(
            "independent midpoint QEMU register states disagree",
        ));
    }
    let mut changed = branch_before.clone();
    let low = changed
        .first_mut()
        .ok_or_else(|| backend_error("selected GDB register has no writable bytes"))?;
    *low ^= args.xor_mask;

    // An already-open relay retains its original read-only access mode.
    client
        .close_debug_relay(branch, &branch_access, branch_relay)
        .await
        .map_err(control_client_error)?;
    let report = sessions
        .fork_branch_for_register_write(
            branch_access.lease(),
            role,
            node,
            format!("gdb-register-{}", args.register),
            changed.clone(),
        )
        .await
        .map_err(|error| backend_error(format!("finding register fork failed: {error}")))?;
    let writable_relay = client
        .open_debug_relay(branch, &branch_access)
        .await
        .map_err(control_client_error)?;
    let command = format!("P{:x}={}", args.register, lower_hex(&changed));
    let response = rsp_exchange(
        client,
        branch,
        &branch_access,
        writable_relay,
        command.as_bytes(),
    )
    .await?;
    if response != b"OK" {
        return Err(backend_error(format!(
            "private QEMU rejected register write: {}",
            String::from_utf8_lossy(&response)
        )));
    }
    let branch_after =
        read_register(client, branch, &branch_access, writable_relay, &register).await?;
    let canonical_after = read_register(
        client,
        canonical,
        &canonical_access,
        canonical_relay,
        &register,
    )
    .await?;
    if branch_after != changed || canonical_after != canonical_before {
        return Err(backend_error(
            "private register write did not read back or changed the canonical QEMU",
        ));
    }
    {
        let plane = sessions.shared_control_plane();
        let plane = plane.lock().await;
        if plane
            .writable_debug_branch(canonical)
            .map_err(|error| backend_error(error.to_string()))?
            .is_some()
            || plane
                .writable_debug_branch(branch)
                .map_err(|error| backend_error(error.to_string()))?
                != Some(report.branch.id)
        {
            return Err(backend_error(
                "finding branch access provenance is inconsistent",
            ));
        }
    }
    client
        .close_debug_relay(branch, &branch_access, writable_relay)
        .await
        .map_err(control_client_error)?;
    client
        .close_debug_relay(canonical, &canonical_access, canonical_relay)
        .await
        .map_err(control_client_error)?;
    client
        .release_debug_controller(branch, &branch_access)
        .await
        .map_err(control_client_error)?;
    client
        .release_debug_controller(canonical, &canonical_access)
        .await
        .map_err(control_client_error)?;

    Ok(RegisterWriteProof {
        branch_id: lower_hex(&report.branch.id.bytes),
        before: canonical_before,
        after: branch_after,
    })
}

async fn read_register(
    client: &RpcControlClient,
    session: SessionRef,
    access: &DebugControllerAccess,
    relay: DebugRelayId,
    register: &str,
) -> Result<Vec<u8>, CliError> {
    let reply = rsp_exchange(client, session, access, relay, register.as_bytes()).await?;
    if reply.is_empty() || !reply.len().is_multiple_of(2) {
        return Err(backend_error(
            "QEMU returned an empty or odd-length GDB register",
        ));
    }
    let mut bytes = Vec::with_capacity(reply.len() / 2);
    for pair in reply.as_chunks::<2>().0 {
        let high = hex_nibble(pair[0]).ok_or_else(|| backend_error("GDB register is not hex"))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| backend_error("GDB register is not hex"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

async fn rsp_exchange(
    client: &RpcControlClient,
    session: SessionRef,
    access: &DebugControllerAccess,
    relay: DebugRelayId,
    payload: &[u8],
) -> Result<Vec<u8>, CliError> {
    let checksum = payload
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    let packet = format!("${}#{checksum:02x}", String::from_utf8_lossy(payload));
    let written = client
        .write_debug_relay(session, access, relay, packet.as_bytes())
        .await
        .map_err(control_client_error)?;
    if written != packet.len() {
        return Err(backend_error("GDB relay accepted a partial request"));
    }

    let mut received = Vec::new();
    let mut initial_stop_seen = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let chunk = client
                .read_debug_relay(session, access, relay, 4096)
                .await
                .map_err(control_client_error)?;
            if chunk.eof {
                return Err(backend_error("GDB relay closed before a reply"));
            }
            received.extend_from_slice(&chunk.bytes);
            if received.len() > 65_536 {
                return Err(backend_error("GDB reply exceeds the bounded relay size"));
            }
            while let Some(start) = received.iter().position(|byte| *byte == b'$') {
                let Some(end) = received[start + 1..].iter().position(|byte| *byte == b'#') else {
                    break;
                };
                let end = start + 1 + end;
                if received.len() < end + 3 {
                    break;
                }
                let body = received[start + 1..end].to_vec();
                let high = hex_nibble(received[end + 1])
                    .ok_or_else(|| backend_error("invalid GDB response checksum"))?;
                let low = hex_nibble(received[end + 2])
                    .ok_or_else(|| backend_error("invalid GDB response checksum"))?;
                let actual = body.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
                if actual != ((high << 4) | low) {
                    return Err(backend_error("GDB response checksum mismatch"));
                }
                received.drain(..end + 3);
                client
                    .write_debug_relay(session, access, relay, b"+")
                    .await
                    .map_err(control_client_error)?;
                if body == b"T05" && !initial_stop_seen {
                    initial_stop_seen = true;
                    continue;
                }
                return Ok(body);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| backend_error("GDB relay response timed out"))?
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
