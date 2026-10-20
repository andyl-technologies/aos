//! Actual CLI wrapper selection of DirectRequired before publication admission.

use std::io::{Read as _, Write as _};
use std::sync::mpsc;

use super::*;

#[tokio::test]
async fn cli_upload_preserves_direct_required_actor_refusal() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("info")).unwrap();
    std::fs::write(root.path().join("HEAD"), "ref: refs/heads/stable\n").unwrap();
    std::fs::write(
        root.path().join("info/refs"),
        format!("{}\trefs/heads/stable\n", "a".repeat(64)),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (sender, received) = mpsc::channel();
    let server = std::thread::spawn(move || {
        for principal in ["aa".repeat(32), "bb".repeat(32)] {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "expected Direct identity control"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(error) => panic!("identity listener: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 1024];
                let count = socket.read(&mut bytes).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&bytes[..count]);
                assert!(request.len() <= 8192);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    if request.len() == end + 4 + length {
                        break;
                    }
                }
            }
            sender
                .send(
                    String::from_utf8_lossy(&request)
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                )
                .unwrap();
            let reply = serde_json::to_vec(&hub_types::WhoAmIResponse {
                deployment_id: "deployment".into(),
                principal_id: principal,
                transfer_mode: "direct_required".into(),
                ..Default::default()
            })
            .unwrap();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
            socket.write_all(&reply).unwrap();
        }
    });
    let access = HubAccessArgs {
        hub: Some(origin),
        token: Some("fixture-token".into()),
        direct_provider_policy: None,
        direct_upload_journal: None,
        new_direct_upload_run: false,
    };

    let result = upload_registry_publication(
        &access,
        "example/main",
        None,
        root.path(),
        &Printer::new(0, true, false),
    )
    .await;

    assert!(result.is_err());
    server.join().unwrap();
    let requests = received.into_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.starts_with("POST /aos.hub.v1.IdentityService/WhoAmI "))
    );
}
