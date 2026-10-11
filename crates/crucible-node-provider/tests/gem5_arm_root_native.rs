//! Exercises the actual source-installed root model and retained kernel custody.

// crucible-lint: allow rust-allow -- invalid actual native fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- fixture construction and validation failures are test-only.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};

use crucible_node_contract::Id;
use crucible_node_provider::gem5::{
    ArmRootCustodySlot, ArmRootLaunch, ArmRootNativeCustody, ArmRootNativeProcess,
};

struct ReservedSlot(Arc<Mutex<Option<ArmRootNativeCustody>>>);

impl ArmRootCustodySlot for ReservedSlot {
    fn retain(self: Box<Self>, custody: ArmRootNativeCustody) {
        let mut retained = self.0.lock().unwrap();
        assert!(retained.is_none());
        *retained = Some(custody);
    }
}

#[test]
#[ignore = "executes the actual installed ARM native process and fixed guest"]
fn actual_root_model_preparation_preserves_native_and_failure_custody() {
    let root = root_native_support::evidence_root("crucible-arm-root-private").unwrap();
    let resource = root.join("resources");
    let images = root.join("images");
    let temporary = root.join("temporary");
    for directory in [&resource, &images, &temporary] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let launch = ArmRootLaunch::installed(
        Id::new("root-node").unwrap(),
        Id::new("initial").unwrap(),
        1.into(),
        resource.clone(),
        images,
        temporary,
        Duration::from_secs(180),
    )
    .unwrap();
    let retained = Arc::new(Mutex::new(None));
    let mut result = ArmRootNativeProcess::spawn(launch, Box::new(ReservedSlot(retained.clone())));
    let observed = match &mut result {
        Ok(process) => {
            let preserved = root.join("preserved");
            fs::create_dir(&preserved).unwrap();
            fs::set_permissions(&preserved, fs::Permissions::from_mode(0o700)).unwrap();
            let qualification = (|| {
                let image = process
                    .capture(Id::new("initial-capture").unwrap(), &preserved)
                    .map_err(|error| std::io::Error::other(format!("capture: {error}")))?;
                let certificate = process
                    .qualify_capture(&image, &root)
                    .map_err(|error| std::io::Error::other(format!("qualify: {error}")))?;
                let authority = process.qualify_exact(&image, &certificate)?;
                let original = process.initial_prepared_session(&authority)?;
                original.packet().0.verify(original.packet().1)?;
                original.transcript().0.verify(original.transcript().1)?;
                assert!(process.next_publication_bound(&authority)?.is_some());
                certificate.verify_image(&image)?;
                Ok::<(), crucible_node_provider::ProviderError>(())
            })();
            match qualification {
                Ok(()) => Ok((
                    process.native_ready().continuation.clone(),
                    process.native_ready().model_scope.model_id.clone(),
                    process.boundary().ordinal.get(),
                )),
                Err(error) => Err(error.to_string()),
            }
        }
        Err(error) => Err(error.to_string()),
    };
    drop(result);
    let mut capsule = retained.lock().unwrap().take().unwrap();
    assert!(capsule.host_ledger().prepared().is_some());
    assert_eq!(capsule.host_ledger().boundary().unwrap().ordinal.get(), 0);
    assert!(capsule.host_ledger().unresolved().is_none());
    capsule.begin_quarantine().unwrap();
    while !capsule.poll_reclamation().unwrap() {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(capsule.poll_reclamation().unwrap());
    match observed {
        Ok((continuation, model, ordinal)) => {
            assert_eq!(continuation, "original");
            assert_eq!(model, "arm-linux-vexpress-atomic-root-functional-v1");
            assert_eq!(ordinal, 0);
        }
        Err(error) => panic!(
            "actual native preparation failed: {error}; {}",
            fs::read_to_string(resource.join("native.stderr")).unwrap()
        ),
    }
}

#[path = "support/root_native.rs"]
mod root_native_support;
