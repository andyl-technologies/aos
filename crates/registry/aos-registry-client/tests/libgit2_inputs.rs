//! Boundary checks for the vendored libgit2 parser and repository formats.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use git2::{Indexer, ObjectFormat, RepositoryInitOptions};
use sha2::{Digest, Sha256};

const MAX_HTTP_REQUEST_BYTES: usize = 16 * 1024;

fn serve_once(listener: TcpListener, response_body: Vec<u8>) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    read_http_headers(&mut stream);

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(&response_body).unwrap();
}

fn read_http_headers(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];

    while request.len() < MAX_HTTP_REQUEST_BYTES {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    return;
                }
            }
            Err(error) => panic!("failed to read smart HTTP request: {error}"),
        }
    }

    panic!("smart HTTP request headers were incomplete or too large");
}

fn truncated_capability_advertisement() -> Vec<u8> {
    let mut body = b"0048".to_vec();
    body.extend(std::iter::repeat_n(b'A', 63));
    body.push(0);
    body.extend_from_slice(b"obje");

    // These bytes are outside the declared packet and must not extend the
    // capability token seen by the packet parser.
    body.extend_from_slice(b"ct-format=");
    body.extend(std::iter::repeat_n(b'F', 16));
    body
}

fn encode_pack_object_header(kind: u8, mut size: usize) -> Vec<u8> {
    let mut byte = (kind << 4) | (size as u8 & 0x0f);
    size >>= 4;
    let mut encoded = Vec::new();

    while size != 0 {
        encoded.push(byte | 0x80);
        byte = size as u8 & 0x7f;
        size >>= 7;
    }
    encoded.push(byte);
    encoded
}

fn encode_offset_distance(mut distance: usize) -> Vec<u8> {
    let mut encoded = vec![(distance & 0x7f) as u8];
    distance >>= 7;

    while distance != 0 {
        distance -= 1;
        encoded.insert(0, 0x80 | (distance & 0x7f) as u8);
        distance >>= 7;
    }
    encoded
}

fn encode_delta_size(mut size: usize) -> Vec<u8> {
    let mut encoded = Vec::new();

    loop {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if size == 0 {
            return encoded;
        }
    }
}

fn compressed(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn oversized_delta_pack() -> Vec<u8> {
    let base = b"a";
    let mut base_entry = encode_pack_object_header(3, base.len());
    base_entry.extend_from_slice(&compressed(base));

    let mut delta = encode_delta_size(base.len());
    delta.extend_from_slice(&encode_delta_size(2 * 1024 * 1024 * 1024 + 1));

    let mut delta_entry = encode_pack_object_header(6, delta.len());
    delta_entry.extend_from_slice(&encode_offset_distance(base_entry.len()));
    delta_entry.extend_from_slice(&compressed(&delta));

    let mut pack = b"PACK".to_vec();
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(&base_entry);
    pack.extend_from_slice(&delta_entry);
    let checksum = Sha256::digest(&pack);
    pack.extend_from_slice(&checksum);
    pack
}

#[test]
fn smart_http_rejects_a_capability_split_across_packet_boundary() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || serve_once(listener, truncated_capability_advertisement()));

    let temporary = tempfile::tempdir().unwrap();
    let repository = git2::Repository::init_bare(temporary.path()).unwrap();
    let mut remote = repository
        .remote_anonymous(&format!("http://{address}/registry.git"))
        .unwrap();
    let error = remote.connect(git2::Direction::Fetch).unwrap_err();

    assert_eq!(error.message(), "error parsing REF pkt-line");
    server.join().unwrap();
}

#[test]
fn pack_indexer_rejects_delta_results_beyond_its_object_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let mut indexer =
        Indexer::new_ext(None, temporary.path(), 0, false, ObjectFormat::Sha256).unwrap();
    let pack = oversized_delta_pack();

    let result = indexer
        .write_all(&pack)
        .map_err(|error| error.to_string())
        .and_then(|_| {
            indexer
                .commit()
                .map(|_| ())
                .map_err(|error| error.to_string())
        });

    let error = result.unwrap_err();
    assert!(
        error.contains("overly large object"),
        "unexpected indexer error: {error}"
    );
}

#[test]
fn vendored_library_retains_repository_formats_and_static_object_parity() {
    let version = git2::Version::get().libgit2_version();
    assert!(
        version >= (1, 9, 7),
        "unexpected libgit2 version {version:?}"
    );

    for (name, format, oid_hex_bytes) in [
        ("sha1", ObjectFormat::Sha1, 40_usize),
        ("sha256", ObjectFormat::Sha256, 64_usize),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let mut options = RepositoryInitOptions::new();
        options.bare(true).object_format(format);
        let repository = git2::Repository::init_opts(temporary.path(), &options).unwrap();

        let object = repository.blob(name.as_bytes()).unwrap();
        assert_eq!(object.to_string().len(), oid_hex_bytes);
        assert_eq!(
            repository.find_blob(object).unwrap().content(),
            name.as_bytes()
        );

        if format == ObjectFormat::Sha256 {
            let static_object = aos_registry_format::object::hash_object(
                aos_registry_format::object::ObjectKind::Blob,
                name.as_bytes(),
            );
            assert_eq!(object.to_string(), static_object.to_hex());
        }
    }
}
