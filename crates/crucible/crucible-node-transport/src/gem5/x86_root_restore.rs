//! Fresh x86 native reconstruction from authenticated model-aware image custody.
//!
//! Historical supplementary-file relocation and future capture directories are
//! separate. No removed source namespace is recreated or opened during import.

use std::{
    fs::{self, OpenOptions},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixListener,
        process::CommandExt,
    },
    path::PathBuf,
    process::Stdio,
    time::Duration,
};

use crucible_node_format::{Id, U64, canonical};
use serde_json::json;

// Reuses only original waitable kernel-group custody; model/peer authority is x86-owned.
use super::arm_root_group::ArmRootGroup as StoppedProcessGroup;
use super::images::validate_private_directory;
use super::x86_root_process::{
    X86RootConstruction, X86RootOrigin, connect, read_with_deadline, selection,
};
use super::{
    X86RootCapturedImage, X86RootCustodySlot, X86RootNativeCustody, X86RootNativeProcess,
    X86RootPreparedSession,
};
use crate::ProviderError;

use super::process::image_process::saved_files_manifest;

/// Supplies only fresh private storage and stronger fencing for reconstruction.
pub struct X86RootRestoreTarget {
    /// Supplies a distinct new owning native incarnation.
    pub incarnation: Id,
    /// Supplies stronger fencing than the captured original generation.
    pub generation: U64,
    /// Names empty canonical private modeled-resource storage.
    pub resource_root: PathBuf,
    /// Names separate empty private storage for fresh captures.
    pub image_root: PathBuf,
    /// Names empty private operational control and restart storage.
    pub temporary_root: PathBuf,
    /// Bounds operational transport and helper deadlines without guest time.
    pub timeout: Duration,
    /// Supplies the fresh target caller's independent construction reservation.
    pub command_budget: super::NativeCommandConstructionBudget,
}

impl X86RootNativeProcess {
    /// Reconstructs the original stopped model behind a fresh authenticated gate.
    ///
    /// This does not reuse source live authority. The reconstructed owner must
    /// independently recapture/audit its own current kernel/task/FD/map closure.
    ///
    /// # Errors
    /// Refuses foreign profile/bytes, stale fencing, shared or occupied routes,
    /// changed native code, invalid Ready or altered original held operation.
    /// Actual child, control and historical packets transfer to mandatory custody
    /// on every failure after spawn.
    pub fn restore(
        image: &X86RootCapturedImage,
        target: X86RootRestoreTarget,
        slot: Box<dyn X86RootCustodySlot>,
    ) -> Result<Self, ProviderError> {
        image.verify()?;
        let installed = super::x86_root_installed::InstalledX86RootModel::load()?;
        if installed.manifest_content()? != image.source().profile
            || target.incarnation == image.source().incarnation
            || target.generation <= image.source().generation
            || target.timeout.is_zero()
            || target.timeout > Duration::from_secs(600)
        {
            return Err(ProviderError::Correlation(
                "x86 reconstruction profile or fencing differs",
            ));
        }
        let roots = [
            &target.resource_root,
            &target.image_root,
            &target.temporary_root,
        ];
        for (index, root) in roots.iter().enumerate() {
            validate_private_directory(root)?;
            if fs::read_dir(root)?.next().is_some() {
                return Err(ProviderError::Correlation(
                    "x86 fresh reconstruction namespace occupied",
                ));
            }
            for other in roots.iter().skip(index + 1) {
                if root.starts_with(other) || other.starts_with(root) {
                    return Err(ProviderError::Correlation(
                        "x86 reconstruction routes overlap",
                    ));
                }
            }
        }
        image.prepare_resources(&target.resource_root)?;
        let supplementary = image.materialized_supplementary_files_root()?;
        let manifest = saved_files_manifest::write(image, &supplementary, &target.temporary_root)?;
        let mut launch = image.source().clone();
        launch.incarnation = target.incarnation;
        launch.generation = target.generation;
        launch.resource_root = target.resource_root;
        launch.tools.image_root = target.image_root;
        launch.tools.temporary_root = target.temporary_root;
        launch.timeout = target.timeout;
        launch.command_budget = Some(target.command_budget);
        let endpoint = launch.tools.temporary_root.join("control.sock");
        let listener = UnixListener::bind(&endpoint)?;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(launch.tools.temporary_root.join("restart.stdout"))?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(launch.tools.temporary_root.join("restart.stderr"))?;
        let host_ledger = super::x86_root_process::X86RootHostLedger::reserve();
        image.control_history().validate()?;
        let mut history = image.control_history().clone();
        history.reserve(3)?;
        history.reserve_session()?;
        use super::native_command::{Atom, CommandSpec};
        let args = [
            Atom::text("--new-coordinator"),
            Atom::text("--coord-port"),
            Atom::text("0"),
            Atom::text("--interval"),
            Atom::text("0"),
            Atom::text("--ckptdir"),
            Atom::path(&launch.tools.image_root),
            Atom::text("--tmpdir"),
            Atom::path(&launch.tools.temporary_root),
            Atom::path(image.process_image()?),
        ];
        let environment = [
            (
                "CRUCIBLE_RESTORE_RESOURCE_ROOT",
                Atom::path(&launch.resource_root),
            ),
            (
                "CRUCIBLE_RESTORE_SAVED_FILES_SOURCE_ROOT",
                Atom::path(image.source_supplementary_files_root()),
            ),
            (
                "CRUCIBLE_RESTORE_SAVED_FILES_TARGET_ROOT",
                Atom::path(&supplementary),
            ),
            (
                "CRUCIBLE_RESTORE_SAVED_FILES_MANIFEST",
                Atom::path(&manifest),
            ),
            (
                "CRUCIBLE_GEM5_OPERATIONAL_ROOT",
                Atom::path(&launch.tools.temporary_root),
            ),
            ("CRUCIBLE_GEM5_CONTROL_SOCKET", Atom::path(&endpoint)),
            (
                "DMTCP_PATH_MAPPING",
                Atom::Mapping(&image.source().resource_root, &launch.resource_root),
            ),
        ];
        let child = CommandSpec {
            executable: &launch.tools.restarter.path,
            temporary_root: &launch.tools.temporary_root,
            args: &args,
            environment: &environment,
        }
        .construct(launch.command_construction_budget()?)?
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
        let custody = X86RootNativeCustody {
            group: None,
            unenrolled: Some(child),
            launch,
            stream: None,
            listener: Some(listener),
            received_ready: None,
            control_frames: Vec::new(),
            history,
            audit_workers: Vec::new(),
            unenrolled_helpers: Vec::new(),
            host_ledger,
        };
        let mut construction = X86RootConstruction::new(custody, slot);
        let outcome = (|| {
            let custody = construction.custody_mut()?;
            custody.group = Some(StoppedProcessGroup::enroll_retained(
                &mut custody.unenrolled,
            )?);
            custody.stream = Some(connect(custody, true)?);
            let original_deadline = super::arm_root_io::deadline(custody.launch.timeout)?;
            let stream = custody
                .stream
                .as_mut()
                .ok_or(ProviderError::Frame("x86 reconstructed control omitted"))?;
            let mut io = super::arm_root_io::NativeDeadlineIo::new(stream, original_deadline);
            let original_bind = json!({"kind":"restore_bind","owner":custody.launch.owner,
                "source_incarnation":image.source().incarnation,"source_generation":image.source().generation,
                "incarnation":custody.launch.incarnation,"generation":custody.launch.generation,
                "capture":image.capture_id()});
            // A failed or unwound constructor retains the exact source lineage
            // and attempted rebinding body instead of regenerating it from paths.
            custody.history.request(&original_bind)?;
            custody.host_ledger.unresolved = Some(original_bind.clone());
            crate::transport::write_frame(&mut io, &original_bind, super::GEM5_NATIVE_FRAME_BYTES)?;
            let frame = read_with_deadline(custody, original_deadline)?;
            custody
                .history
                .push(super::X86RootControlKind::Ready, frame.1.clone())?;
            custody.received_ready = Some(frame.1);
            let ready: super::x86_root_model::Gem5X86RootNativeReady =
                serde_json::from_value(frame.0)
                    .map_err(|_| ProviderError::Frame("x86 reconstructed typed Ready shape"))?;
            ready.validate_selection(
                &selection(&custody.launch)?,
                &custody.launch.owner,
                &custody.launch.incarnation,
                custody.launch.generation,
            )?;
            if ready.continuation != "restored" || ready.boundary != *image.boundary() {
                return Err(ProviderError::Correlation(
                    "x86 reconstructed incarnation or state differs",
                ));
            }
            let group = custody
                .group
                .as_ref()
                .ok_or(ProviderError::Frame("x86 fresh kernel peer omitted"))?;
            group.require_live()?;
            let (pid, ticks) = group.identity();
            let start_ticks = ticks.to_owned();
            let source_scope = custody.launch.scope()?;
            let bytes = custody
                .received_ready
                .as_ref()
                .ok_or(ProviderError::Frame("x86 fresh original packet omitted"))?
                .clone();
            let packet = canonical::content_ref(&bytes, "application/json")?;
            let transcript_bytes = canonical::canonical_json(&json!({
                "format":"crucible.gem5.x86-root-prepared-session","version":1,"origin":"restored",
                "source_capture":image.capture_id(), "pid":pid,"start_ticks":start_ticks,
                "source_scope":source_scope,"profile":custody.launch.profile,"ready_packet":packet,
                "owner":custody.launch.owner,"incarnation":custody.launch.incarnation,"generation":custody.launch.generation}))?;
            let transcript = canonical::content_ref(&transcript_bytes, "application/json")?;
            let token = Id::new(format!("gem5/x86-root/prepared/{}", transcript.hash.digest))?;
            Ok((
                ready,
                X86RootPreparedSession {
                    pid,
                    start_ticks,
                    source_scope,
                    packet,
                    bytes,
                    transcript,
                    transcript_bytes,
                    token,
                    origin: X86RootOrigin::Restored {
                        source_capture: image.capture_id().clone(),
                    },
                },
            ))
        })();
        let (ready, prepared) = outcome?;
        construction.custody_mut()?.history.prepared(&prepared)?;
        let (mut custody, slot) = construction.adopt()?;
        custody.host_ledger.unresolved = None;
        let mut process = Self {
            quarantined: false,
            custody: Some(custody),
            slot: Some(slot),
            boundary: ready.boundary.clone(),
            ready,
            prepared: Some(prepared),
            completed: image.completed.clone(),
            pending: image.pending.clone(),
            last_acknowledged: image.last_acknowledged().cloned(),
            unresolved: None,
            unresolved_capture: None,
        };
        // Authenticate the actual held native request/FIFO before any new callback.
        // Historical Rust data alone cannot establish reconstructed output custody.
        if let Some(pending) = process.pending.clone() {
            let retained = process
                .completed
                .get(&pending)
                .cloned()
                .ok_or(ProviderError::Frame(
                    "x86 captured pending original omitted",
                ))?;
            let actual = process.exchange(
                serde_json::to_value(retained.original())
                    .map_err(|_| ProviderError::Frame("x86 original pending encoding"))?,
            )?;
            let expected = canonical::parse_json(retained.bytes(), super::GEM5_NATIVE_FRAME_BYTES)?;
            if actual != expected {
                return Err(ProviderError::Correlation(
                    "x86 restored original held prefix/FIFO differs",
                ));
            }
        }
        Ok(process)
    }
}
