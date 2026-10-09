//! Actual borrowed installed adoption preserves complete two-group source custody.
//!
//! This component uses the distinctly measured lineage source, not legacy source
//! authority. It proves owning callback failure and truthful operational group
//! reclamation; common runtime association and source qualification remain next.

#![cfg(target_os = "linux")]
// crucible-lint: allow panic-shortcut -- A native original mismatch invalidates this component witness.
#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use crucible_node_contract::U64;
use crucible_node_provider::client::LineageWindowRequests;
use crucible_node_provider::reference_lineage::{LineageSourceCustody, LineageSourceCustodySlot};

#[path = "lineage_guarded/client.rs"]
mod client;
#[path = "lineage_guarded/fixture.rs"]
mod fixture;
#[path = "lineage_guarded/installed.rs"]
mod installed;
#[path = "lineage_guarded/lifecycle.rs"]
mod lifecycle;
#[path = "lineage_guarded/scenario.rs"]
mod scenario;
#[path = "lineage_guarded/sdk_plan.rs"]
mod sdk_plan;

struct Slot(Rc<RefCell<Option<LineageSourceCustody>>>);

impl LineageSourceCustodySlot for Slot {
    fn identity(&self) -> U64 {
        U64::new(1)
    }

    fn retain(self: Box<Self>, custody: LineageSourceCustody) {
        let mut retained = self.0.borrow_mut();
        assert!(
            retained.is_none(),
            "one original reservation cannot be replaced"
        );
        *retained = Some(custody);
    }
}

#[test]
#[ignore = "Requires the controller-bound current source-built lineage implementation."]
fn borrowed_installed_callback_unwind_keeps_original_window_and_both_groups() {
    let installation = installed::PackageSelection::from_environment().unwrap();

    // The whole two-group slot exists before fixture launch or private bootstrap.
    let retained = Rc::new(RefCell::new(None));
    let slot = Box::new(Slot(Rc::clone(&retained)));
    let (service, guard) = fixture::NativeService::launch(
        installation.provider_path(),
        installation.device_path(),
        false,
        slot,
    );
    let (handshake, controller) = client::connect(&service);
    let mut guard = guard
        .attach(controller, handshake)
        .unwrap_or_else(|failure| panic!("original attached scope: {}", failure.error));
    let complete_plan = lifecycle::native_window(&service);
    let realized = complete_plan
        .steps
        .iter()
        .position(|step| {
            matches!(step,
                crucible_node_provider::conformance::ProbeStep::Exchange { id, .. }
                if id.as_str() == "realize-withheld"
            )
        })
        .unwrap();
    let completed = complete_plan
        .steps
        .iter()
        .position(|step| {
            matches!(step,
                crucible_node_provider::conformance::ProbeStep::Exchange { id, .. }
                if id.as_str() == "execute-native-window"
            )
        })
        .unwrap();
    let mut initial = complete_plan.clone();
    initial.steps.truncate(realized + 1);
    let bindings = sdk_plan::execute(
        &mut guard,
        &service,
        &initial,
        service.private_bindings.clone(),
    );
    let realization = fixture::id("realize");
    let ready = guard
        .with_original_realization(&realization, |view| {
            let (request, response) = view.native_initialization()?;
            Ok((
                view.native_pid(),
                view.native_start_ticks(),
                request.to_vec(),
                response.to_vec(),
            ))
        })
        .unwrap();
    let enrollment = guard
        .with_original_realization(&realization, |view| {
            installed::enroll(
                &installation,
                service.pid,
                &view,
                &service.bootstrap.resource_limits,
            )
        })
        .unwrap();
    let same = guard
        .with_original_realization(&realization, |view| {
            installed::enroll(
                &installation,
                service.pid,
                &view,
                &service.bootstrap.resource_limits,
            )
        })
        .unwrap();
    assert_eq!(same, enrollment);
    // Source-owned Ready bytes alone cannot accept another provider process.
    assert!(
        guard
            .with_original_realization(&realization, |view| {
                installed::enroll(
                    &installation,
                    std::process::id(),
                    &view,
                    &service.bootstrap.resource_limits,
                )
            })
            .is_err()
    );
    // The host cannot signal the numeric native group through a foreign reaper.
    // This refusal leaves the actual source and original Ready available.
    assert!(guard.poll_reclamation().is_err());
    assert!(Path::new(&format!("/proc/{}", ready.0.get())).exists());
    let refused: Result<(), _> = guard.with_original_realization(&realization, |view| {
        assert_eq!(view.native_pid(), ready.0);
        Err(crucible_node_provider::ProviderError::Correlation(
            "installed source adopter refused",
        ))
    });
    assert!(refused.is_err());
    assert!(retained.borrow().is_none());
    guard
        .with_original_realization(&realization, |view| {
            let (request, response) = view.native_initialization()?;
            assert_eq!(view.native_start_ticks(), ready.1);
            assert_eq!(request, ready.2);
            assert_eq!(response, ready.3);
            Ok(())
        })
        .unwrap();

    let mut before = complete_plan.clone();
    before.steps.truncate(completed + 1);
    before.steps.drain(1..realized + 1);
    let bindings = sdk_plan::execute(&mut guard, &service, &before, bindings);
    let input = fixture::id("input");
    let begin = fixture::id("begin-window");
    let requests = || LineageWindowRequests {
        realization: &realization,
        input: &input,
        begin: &begin,
    };
    let original = guard
        .with_original_window(requests(), |view| {
            let (request, response) = view.native_close()?;
            Ok((
                view.native_pid(),
                view.native_receipt().clone(),
                request.to_vec(),
                response.to_vec(),
                view.measurement_reference().clone(),
                view.consumption_relation_reference().clone(),
            ))
        })
        .unwrap();

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), _> = guard.with_original_window(requests(), |view| {
            assert_eq!(view.native_receipt(), &original.1);
            panic!("installed adopter failed while copying genuine original evidence");
        });
    }));
    assert!(unwind.is_err());
    assert!(
        retained.borrow().is_none(),
        "callback never transfers the owning capsule"
    );
    guard
        .with_original_window(requests(), |view| {
            let (request, response) = view.native_close()?;
            assert_eq!(view.native_receipt(), &original.1);
            assert_eq!(request, original.2);
            assert_eq!(response, original.3);
            assert_eq!(view.measurement_reference(), &original.4);
            assert_eq!(view.consumption_relation_reference(), &original.5);
            assert!(view.observation().events[0].causal_parent_ids.is_empty());
            assert!(Path::new(&format!("/proc/{}", original.0.get())).exists());
            Ok(())
        })
        .unwrap();

    // Finish only the authentic retained public close/retire/shutdown suffix.
    // Source shutdown owns the native Child wait; the host never invents it.
    let mut suffix = lifecycle::native_window(&service);
    suffix.steps.drain(1..completed + 1);
    sdk_plan::execute(&mut guard, &service, &suffix, bindings);
    assert!(!Path::new(&format!("/proc/{}", original.0.get())).exists());
    let provider = service.pid;
    drop(guard);
    let mut capsule = retained.borrow_mut().take().unwrap();
    assert_eq!(capsule.provider_pid(), provider);
    assert_eq!(
        capsule.native_pid(),
        Some(u32::try_from(original.0.get()).unwrap())
    );
    assert!(capsule.native_scope_resolved());
    let mut reclaimed = false;
    for _ in 0..300 {
        if capsule.poll_reclamation().unwrap() {
            reclaimed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(reclaimed, "original two-group reclamation unresolved");
    assert!(!Path::new(&format!("/proc/{provider}")).exists());
    std::fs::remove_dir_all(capsule.private_directory()).unwrap();
}
