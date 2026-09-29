//! Real selected-Hub source preflight before metadata credentials or admission.

use std::os::unix::fs::OpenOptionsExt as _;

use super::*;

#[tokio::test]
async fn fifo_inventory_refuses_without_a_writer_or_any_hub_network() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inventory.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let auth = AuthOptions {
        hub_origin: Some(origin.clone()),
        hub_registry: Some("registry".into()),
        token: Some("private-provisioning-canary".into()),
        ..Default::default()
    };
    let file = StaticOriginFile {
        relative_path: "objects/source".into(),
        source: path.clone(),
        class: super::super::StaticOriginClass::Mutable,
        content_type: "application/octet-stream",
        cache_control: "no-cache",
        content_disposition: None,
        sha256: None,
        byte_size: None,
    };

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        stage_if_selected(&format!("{origin}/registry"), &[file], &auth),
    )
    .await;
    if result.is_err() {
        // Permit the previous blocking opener to finish on regression failure.
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
            .open(&path);
    }

    assert!(result.unwrap().is_err());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}
