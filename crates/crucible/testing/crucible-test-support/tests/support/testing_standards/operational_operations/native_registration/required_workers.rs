//! Binds required Native readiness to its same startup Original and owners.
//!
//! Only genuine current/EAGAIN observation repeats. Birth and sole-stream
//! handoff are once-only effects outside that wait; source matching grants no
//! Source activation, native allocation floor or physical-return authority.

use super::super::{Companion, Contract};

const WAIT_READY: &str = r#"loop {
    let slice = setup.original_startup_slice().map_err(|source| Error::Original { source })?;
    let status = (api.current)(material.id, material.runtime);
    self.readiness = Some(status);
    let post = setup.check_original_startup();
    if let Err(source) = &post { self.readiness_post.get_or_insert(*source); }
    if status != 0 && status != -libc::EAGAIN {
        native_status("required pair readiness", status)?;
    }
    post.map_err(|source| Error::Original { source })?;
    if status == 0 { return Ok(()); }
    std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
}"#;

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-qemu-plugin",
    target: "src/runtime/required_workers/owner",
    required: &[
        (r#"loop {"#, 1),
        (r#"while "#, 0),
        (r#"Instant::now("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"SourceOperationClass::"#, 0),
        (r#".begin("#, 0),
        (
            r#"pub(in crate::runtime) fn wait_ready(&mut self, setup: &PluginSetupCompletion,) -> Result<(), Error> {
self.check_process()?; let material = self.material.ok_or(Error::Native {
operation: "required pair", status: -libc::ENOKEY, })?;
let api = self.run.handle()?.api; loop {"#,
            1,
        ),
        (
            r#"if self.attempted { return native_status("duplicate creation", -libc::EALREADY); }
let api = abi::Api::resolve().map_err(|status| Error::Native { operation: "SDK resolution", status, })?;
self.id = material.id; self.api = Some(api); self.attempted = true;"#,
            1,
        ),
        (
            r#"Kind::Run => (api.create_run)(material.id, material.runtime, material.run, child, raw,
self.field.creation_address(),),
Kind::Teardown => (api.create_teardown)(material.id, material.runtime, material.teardown,
child, raw, self.field.creation_address(),),"#,
            1,
        ),
        (
            r#"self.history.creation = Some(status); self.field.record_birth();
native_status("creation", status)?;"#,
            1,
        ),
        (
            r#"let status = self.field.transfer(|creation, canonical| (api.transfer)(material.id, creation, canonical));
self.history.transfer = Some(status); native_status("transfer", status)?;
if !self.field.creation_consumed() { return native_status("transfer disposition", -libc::EPROTO); }"#,
            1,
        ),
        (
            r#"let material = setup.required_worker_material().map_err(|source| Error::Original { source })?;
self.material = Some(material);"#,
            1,
        ),
        (
            r#"for kind in [Kind::Run, Kind::Teardown] {
setup.check_runtime_installation().map_err(|source| Error::Original { source })?;
let (owner, input) = match kind {
Kind::Run => (&mut self.run, std::ptr::null_mut()),
Kind::Teardown => (&mut self.teardown, &mut self.pending_teardown as *mut _), };"#,
            1,
        ),
        (
            r#"let birth = owner.create(material, child, input, Arc::clone(workers), Arc::clone(router), interrupt,);
let post = setup.check_runtime_installation();
if let Err(source) = &post { owner.history.installation_post.get_or_insert(*source); }
birth?; post.map_err(|source| Error::Original { source })?;"#,
            1,
        ),
        (
            r#"if self.run.history.handoff.is_some() || self.stream.is_some() {
return native_status("duplicate stream handoff", -libc::EALREADY); }
self.stream = stream.take();"#,
            1,
        ),
        (
            r#"let status = (handle.api.handoff)(handle.id, handle.pointer(), std::ptr::from_mut(&mut input).cast(),);
self.run.history.handoff = Some(status); self.run.history.handoff_moved = input.moved;
self.run.history.handoff_commit = input.committed_status;
let observation = self.run.observe(); native_status("stream handoff", status)?; let journal = observation?;"#,
            1,
        ),
        (
            r#"if !input.moved || self.stream.is_some() || input.committed_status != Some(0)
|| journal.handoff_committed != 1 || journal.handoff_released != 1 {
return native_status("stream handoff disposition", -libc::EPROTO); }"#,
            1,
        ),
        (
            r#"if let Err(source) = post { self.run.history.handoff_post.get_or_insert(*source); }"#,
            1,
        ),
    ],
    expressions: &[(WAIT_READY, 1)],
    identifiers: &[],
    companions: &[
        super::ORIGINAL_SETUP,
        super::ORIGINAL_SLICE,
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/runtime.rs",
            required: &[
                (
                    r#".required_workers.create(&state.setup, child, &state.workers, &state.teardown_router)
.map_err(|source| PluginRuntimeInstallError::RequiredWorkers { source })?;
state.required_workers.wait_ready(&state.setup)
.map_err(|source| PluginRuntimeInstallError::RequiredWorkers { source })"#,
                    1,
                ),
                (
                    r#"if let Err(error) = retained.registered_mut()?.create_required_workers() {
return Err(fail_post_registration_before_ready_ack_lifecycle(&mut control_stream, error,
&mut acknowledgement_state,)); } acknowledgement_state = PostRegistrationAckState::ReadyAttempted;"#,
                    1,
                ),
                (
                    r#"state.setup.check_original_startup().map_err(|source| PluginRuntimeInstallError::StartupSource { source })?;
let result = state.required_workers.handoff(stream); let post = state.setup.check_original_startup();
state.required_workers.record_handoff_post(&post);
result.map_err(|source| PluginRuntimeInstallError::RequiredWorkers { source })?;
post.map_err(|source| PluginRuntimeInstallError::StartupSource { source })"#,
                    1,
                ),
                (
                    r#"let mut stream = Some(control_stream);
if let Err(error) = callbacks_registered.handoff_run_control(&mut stream) { fatal_policy.terminate(error); }
let workers = callbacks_registered.worker_quiescence();
if let Err(source) = workers.wait_initial_ready(|| callbacks_registered.original_startup_slice())
.and_then(|()| callbacks_registered.complete_original_startup_registration())"#,
                    1,
                ),
                (
                    r#"callbacks_registered.handoff_run_control(&mut stream)"#,
                    1,
                ),
                (r#"retained.registered_mut()?.create_required_workers()"#, 1),
                (
                    r#"if let Err(source) = control_stream.enter_run_via_shared_memory() {
fatal_policy.terminate(PluginRuntimeInstallError::ControlLifecycle { source }); }
match control_stream.plugin_run_io_mut() { Ok(control) => control.enter_run(),"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/startup_source/runtime_purpose.rs",
            required: &[
                (
                    r#"self.check_runtime_installation()?; let state = &self.runtime_reservation;
if state.run_claim_address == 0 || state.teardown_claim_address == 0 {
return Err(StartupSourceError::Ownership { reason: "required worker claims are absent", }); }
Ok(RequiredMaterial { id: self.plugin_id, runtime: state.purpose_address as *mut RuntimePurpose,
run: state.run_claim_address as *mut RunClaim, teardown: state.teardown_claim_address as *mut TeardownClaim, })"#,
                    1,
                ),
                (
                    r#"if !run_claim.is_null() { self.runtime_reservation.run_claim_address = run_claim as usize; }
if !teardown_claim.is_null() { self.runtime_reservation.teardown_claim_address = teardown_claim as usize; }
if result != 0 { self.return_unborn_required_workers(); }
self.accept_status(result)?;"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/runtime/native_worker/owner.rs",
            required: &[
                (
                    r#"pub(in crate::runtime) fn record_birth(&mut self) -> *mut T {
self.projection = self.creation; self.projection }"#,
                    1,
                ),
                (
                    r#"self.transfer_attempted = true; transfer(&mut self.creation, self.canonical.get())"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/runtime/required_workers/control.rs",
            required: &[
                (
                    r#"let _identity = match control.workers.register_current(control.native.kind.mask()) {
Ok(identity) => identity, Err(error) => { control.refuse(Cause::Registration(error)); return -libc::EIO; } };
let idle = control.workers.idle(control.native.kind.mask());"#,
                    1,
                ),
                (
                    r#"if state.read_attempted { return -libc::EALREADY; } state.read_attempted = true;"#,
                    1,
                ),
                (
                    r#"let ready = (control.native.api.ready)(control.native.pointer());
control.lock().native[NativeCut::Ready as usize] = Some(ready);
if ready == -libc::ECANCELED { return ready; }"#,
                    1,
                ),
                (
                    r#"if !control.workers.wait_run_control_started(&control.closing) { return -libc::ECANCELED; }"#,
                    1,
                ),
                (r#"*slot = self.stream.take();"#, 1),
            ],
        },
        Companion {
            path: "crates/crucible/qemu/crucible-qemu-plugin/src/runtime/required_workers/module.rs",
            required: &[
                (
                    r#"if control.native.kind != Kind::Run || control.native.id != id
|| control.owner_process != std::process::id() { return -libc::EPERM; }"#,
                    1,
                ),
                (
                    r#"if state.handoff_attempted || slot.is_some() { return -libc::EALREADY; }
state.handoff_attempted = true;
let Some(stream) = (unsafe { &mut *input.stream }).take() else { return -libc::ENOKEY; };
*slot = Some(stream); input.moved = true; drop(slot); drop(state);
let status = (control.native.api.handoff_committed)(frame);
input.committed_status = Some(status); control.lock().handoff_committed_status = Some(status);"#,
                    1,
                ),
            ],
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{mask_contract, read_companions, replace_one_obligation, source_pattern};

    fn rejects(code: &str, companions: &[String]) {
        assert_eq!(mask_contract(&CONTRACT, code, companions), code);
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", code).is_empty());
        let composed = super::super::super::super::mask_after_operations(
            CONTRACT.package,
            CONTRACT.target,
            code,
        );
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &composed).is_empty());
    }

    #[test]
    fn required_worker_readiness_keeps_original_posts_and_once_only_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), CONTRACT.package)
            .join(format!("{}.rs", CONTRACT.target));
        let source = std::fs::read_to_string(path)?;
        let code = crate::scrub_comments_and_strings(&source);
        let companions = read_companions(&CONTRACT)?;
        assert!(
            crate::flaky_escape_failures(CONTRACT.package, CONTRACT.target, &source).is_empty()
        );
        assert!(
            crate::flaky_escape_failures(
                "unreviewed",
                "unreviewed",
                &mask_contract(&CONTRACT, &code, &companions)
            )
            .is_empty()
        );

        let cases = [
            (
                "setup.original_startup_slice()",
                "renewed_original.wait_slice()",
            ),
            (
                "(api.current)(material.id, material.runtime)",
                "(api.current)(material.id, foreign_runtime)",
            ),
            (
                "self.readiness = Some(status);",
                "discard_readiness(status);",
            ),
            (
                "let post = setup.check_original_startup();",
                "let post = Ok(());",
            ),
            (
                "if status != 0 && status != -libc::EAGAIN",
                "if status != 0 && status != -libc::EBUSY",
            ),
            (
                "post.map_err(|source| Error::Original { source })?; if status == 0 { return Ok(()); }",
                "if status == 0 { return Ok(()); } post.map_err(|source| Error::Original { source })?;",
            ),
            (
                "std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));",
                "std::thread::sleep(std::time::Duration::from_millis(10));",
            ),
            (
                "std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));",
                "loop { std::thread::sleep(slice.min(std::time::Duration::from_millis(10))); }",
            ),
        ];
        for (before, after) in cases {
            let changed_loop = replace_one_obligation(WAIT_READY, &source_pattern(before), after);
            assert_ne!(changed_loop, WAIT_READY, "missing wait mutation: {before}");
            let changed = replace_one_obligation(&code, &source_pattern(WAIT_READY), &changed_loop);
            rejects(&changed, &companions);
        }

        for (before, after) in [
            (
                "self.history.creation = Some(status); self.field.record_birth(); native_status(\"creation\", status)?;",
                "native_status(\"creation\", status)?; self.history.creation = Some(status); self.field.record_birth();",
            ),
            (
                "(api.transfer)(material.id, creation, canonical)",
                "(api.transfer)(material.id, foreign_creation, canonical)",
            ),
            (
                "Kind::Run => (api.create_run)(material.id, material.runtime, material.run, child, raw, self.field.creation_address(),)",
                "Kind::Run => (api.create_run)(material.id, material.runtime, material.teardown, child, raw, self.field.creation_address(),)",
            ),
            (
                "owner.history.installation_post.get_or_insert(*source);",
                "discard_post(*source);",
            ),
            (
                "if self.run.history.handoff.is_some() || self.stream.is_some()",
                "if false",
            ),
            (
                "journal.handoff_committed != 1 || journal.handoff_released != 1",
                "journal.handoff_committed != 1",
            ),
        ] {
            let changed = replace_one_obligation(&code, &source_pattern(before), after);
            assert_ne!(changed, code, "missing ownership mutation: {before}");
            rejects(&changed, &companions);
        }
        Ok(())
    }

    #[test]
    fn required_worker_callers_preserve_real_roles_handoff_and_identity_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::workspace_root();
        let source = std::fs::read_to_string(
            crate::workspace::package_path(&root.join("crates"), CONTRACT.package)
                .join(format!("{}.rs", CONTRACT.target)),
        )?;
        let code = crate::scrub_comments_and_strings(&source);
        let companions = read_companions(&CONTRACT)?;
        assert!(
            crate::flaky_escape_failures(
                "unreviewed",
                "unreviewed",
                &mask_contract(&CONTRACT, &code, &companions)
            )
            .is_empty()
        );

        for (suffix, before, after) in [
            (
                "/setup.rs",
                "self.original_startup()?.wait_slice()",
                "renewed_original.wait_slice()",
            ),
            (
                "/startup_source.rs",
                "(api.query_slice)(self.plugin_id, &mut bounded_ns)",
                "(api.unbounded_slice)(self.plugin_id, &mut bounded_ns)",
            ),
            (
                "/runtime.rs",
                "state.required_workers.wait_ready(&state.setup)",
                "state.required_workers.wait_ready(&foreign_setup)",
            ),
            (
                "/runtime.rs",
                "let post = state.setup.check_original_startup();",
                "let post = Ok(());",
            ),
            (
                "/runtime.rs",
                "state.required_workers.record_handoff_post(&post);",
                "discard_handoff_post(&post);",
            ),
            (
                "/runtime.rs",
                "callbacks_registered.handoff_run_control(&mut stream)",
                "callbacks_registered.handoff_run_control(&mut foreign_stream)",
            ),
            (
                "/runtime.rs",
                ".wait_initial_ready(|| callbacks_registered.original_startup_slice())",
                ".wait_initial_ready(|| renewed_original.wait_slice())",
            ),
            (
                "/runtime.rs",
                ".and_then(|()| callbacks_registered.complete_original_startup_registration())",
                "",
            ),
            (
                "/startup_source/runtime_purpose.rs",
                "if state.run_claim_address == 0 || state.teardown_claim_address == 0",
                "if false",
            ),
            (
                "/runtime/native_worker/owner.rs",
                "self.projection = self.creation;",
                "self.projection = std::ptr::null_mut();",
            ),
            (
                "/runtime/required_workers/control.rs",
                "register_current(control.native.kind.mask())",
                "register_current(Kind::Run.mask())",
            ),
            (
                "/runtime/required_workers/control.rs",
                "if state.read_attempted",
                "if false",
            ),
            (
                "/runtime/required_workers/module.rs",
                "state.handoff_attempted = true;",
                "",
            ),
            (
                "/runtime/required_workers/module.rs",
                "drop(slot); drop(state);",
                "",
            ),
        ] {
            let index = CONTRACT
                .companions
                .iter()
                .position(|binding| binding.path.ends_with(suffix))
                .ok_or("missing actual producer companion")?;
            let original = crate::scrub_comments_and_strings(&companions[index]);
            let changed = replace_one_obligation(&original, &source_pattern(before), after);
            assert_ne!(
                changed, original,
                "missing producer mutation: {suffix}: {before}"
            );
            let mut altered = companions.clone();
            altered[index] = changed;
            rejects(&code, &altered);
        }
        Ok(())
    }
}
