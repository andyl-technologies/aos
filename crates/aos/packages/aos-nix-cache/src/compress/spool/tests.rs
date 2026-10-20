//! Exact bounded disk bytes, process failure and actual AOS codec qualification.

use super::*;
use std::io::{Cursor, Read as _};

fn shell(script: &str) -> Command {
    // Test gates run in the pinned AOS dev shell, whose bash is built by AOS.
    let mut command = Command::new("bash");
    command.args(["-c", script]);
    command
}

#[test]
fn disk_spool_retains_exact_bytes_digest_bound_and_redacted_debug() {
    let bytes = b"private-payload-canary".repeat(100_000);
    let spool = copy_spool(
        &mut Cursor::new(&bytes),
        bytes.len() as u64,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(spool.byte_size(), bytes.len() as u64);
    assert_eq!(spool.sha256(), hex::encode(Sha256::digest(&bytes)));
    assert!(!format!("{spool:?}").contains("private-payload-canary"));
    let (mut file, _, _) = spool.into_parts();
    let mut actual = Vec::new();
    file.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    assert!(
        copy_spool(
            &mut Cursor::new(&bytes),
            (bytes.len() - 1) as u64,
            &AtomicBool::new(false)
        )
        .is_err()
    );
}

#[test]
fn successful_codec_never_admits_output_from_failed_source_dump() {
    let result = pipeline(
        shell("printf private-payload-canary; exit 42"),
        Some(shell(
            "while IFS= read -r -n 1 byte; do printf '%s' \"$byte\"; done",
        )),
        1024,
        &AtomicBool::new(false),
    );
    let error = result.unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-payload-canary"));
}

#[test]
fn failed_codec_cancelled_copy_and_disk_limit_never_return_partial_spool() {
    assert!(
        pipeline(
            shell("printf private-payload-canary"),
            Some(shell("printf private-payload-canary; exit 43")),
            1024,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(
        pipeline(
            shell("printf '%65536s' x"),
            None,
            1024,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(
        pipeline(
            shell("printf private-payload-canary"),
            None,
            1024,
            &AtomicBool::new(true)
        )
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires an explicitly pinned realized AOS source and actual codecs"]
async fn actual_nix_dump_zstd_and_xz_spool_roundtrip_exact_nar_bytes() {
    let source = std::env::var("AOS_DIRECT_TEST_STORE_PATH").unwrap();
    let original = streaming_compress_to_file(&source, "none", 0, 1024 * 1024)
        .await
        .unwrap();
    let original_size = original.byte_size();
    let original_sha = original.sha256().to_owned();
    for codec in ["zstd", "xz"] {
        let spool = streaming_compress_to_file(&source, codec, 3, 1024 * 1024)
            .await
            .unwrap();
        let (file, _, _) = spool.into_parts();
        let mut decoder = ChildCustody(Some(
            Command::new(codec)
                .args(["-d", "-c"])
                .stdin(Stdio::from(file))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let mut input = decoder.0.as_mut().unwrap().stdout.take().unwrap();
        let decoded = copy_spool(&mut input, 1024 * 1024, &AtomicBool::new(false)).unwrap();
        drop(input);
        decoder.finish().unwrap();
        assert_eq!(decoded.byte_size(), original_size);
        assert_eq!(decoded.sha256(), original_sha);
    }
}
