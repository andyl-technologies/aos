//! Checks exact later rename refusal inside a real retained immutable cohort.

use super::*;

fn manifest_cohort(root: &std::path::Path, held: &HeldLock) -> (NativeFsEffect, Receipt) {
    let owner = MetadataStamp::checked(&held.file.metadata().unwrap())
        .unwrap()
        .owner;
    let policy = FencePolicy::Payload { owner };
    let installs: Vec<_> = ["shard-0.idx", "MANIFEST"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| Install {
            temporary: root.join(format!(".terrane-tmp:targeted-{index}")),
            target: root.join(name),
            bytes: format!("canonical target {index}").into_bytes(),
            policy,
        })
        .collect();
    let reads = installs
        .iter()
        .flat_map(|install| [&install.temporary, &install.target])
        .map(|path| ExactRead {
            path: path.clone(),
            expected: None,
            identity: None,
            metadata: None,
            policy,
            owner,
            parents: parents(path),
        })
        .collect();
    let (plan, receipt) = request(installs);
    let mut effect = effect(held, plan);
    effect.preimages = reads;
    (effect, receipt)
}

#[test]
fn targeted_manifest_rename_fault_preserves_installed_prefix_and_refuses_receipt() {
    let (root, held) = fixture();
    let (mut effect, receipt) = manifest_cohort(&root, &held);
    effect
        .faults
        .push(EffectFault::BeforeRenameAt(root.join("MANIFEST")));

    let failure = effect.execute_inline().unwrap_err();
    assert!(matches!(failure, NativeEffectFailure::Io(error)
        if error.to_string() == "injected retained rename failure"));
    assert!(receipt.take().is_err());

    // Reaching the exact second rename requires the first target's actual
    // installation/rebind and the second body's staging and file sync.
    assert_eq!(
        std::fs::read(root.join("shard-0.idx")).unwrap(),
        b"canonical target 0"
    );
    assert!(!root.join(".terrane-tmp:targeted-0").exists());
    assert_eq!(
        std::fs::read(root.join(".terrane-tmp:targeted-1")).unwrap(),
        b"canonical target 1"
    );
    assert!(!root.join("MANIFEST").exists());

    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn targeted_manifest_rename_fault_ignores_other_destinations() {
    let (root, held) = fixture();
    let (mut effect, receipt) = manifest_cohort(&root, &held);
    effect
        .faults
        .push(EffectFault::BeforeRenameAt(root.join("other-MANIFEST")));

    effect.execute_inline().unwrap();
    receipt.take().unwrap();

    for (index, target) in ["shard-0.idx", "MANIFEST"].into_iter().enumerate() {
        assert_eq!(
            std::fs::read(root.join(target)).unwrap(),
            format!("canonical target {index}").into_bytes()
        );
        assert!(!root.join(format!(".terrane-tmp:targeted-{index}")).exists());
    }
    assert!(!root.join("other-MANIFEST").exists());

    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}
