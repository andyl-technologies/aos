//! Tree-walk test support: temporary-file, git, and HTTP/tarball fixtures.

use super::super::*;
use sha2::{Digest, Sha256};

pub(crate) fn unique_temp_dir(prefix: &str) -> PathBuf {
    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_nanos();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "aos-nix-{prefix}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp directory creates");
    dir
}

pub(crate) fn temp_file_with_bytes(prefix: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
    let dir = unique_temp_dir(prefix);
    let path = dir.join("data.txt");
    fs::write(&path, bytes).expect("temp file writes");
    (dir, path)
}

pub(crate) fn git_signature_with_offset(
    seconds: i64,
    offset_minutes: i32,
) -> git2::Signature<'static> {
    let time = git2::Time::new(seconds, offset_minutes);
    git2::Signature::new("AOS Test", "aos@example.invalid", &time).expect("git signature creates")
}

pub(crate) fn git_commit_index(repo: &git2::Repository, message: &str, seconds: i64) -> git2::Oid {
    git_commit_index_with_offset(repo, message, seconds, 0)
}

pub(crate) fn git_commit_index_with_offset(
    repo: &git2::Repository,
    message: &str,
    seconds: i64,
    offset_minutes: i32,
) -> git2::Oid {
    let mut index = repo.index().expect("git index opens");
    index.write().expect("git index writes");
    let tree_id = index.write_tree().expect("git tree writes");
    let tree = repo.find_tree(tree_id).expect("git tree exists");
    let signature = git_signature_with_offset(seconds, offset_minutes);
    let parent_commits = repo
        .head()
        .ok()
        .and_then(|head| head.peel_to_commit().ok())
        .into_iter()
        .collect::<Vec<_>>();
    let parents = parent_commits.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .expect("git commit creates")
}

pub(crate) fn git_commit_file(
    repo: &git2::Repository,
    relative_path: &str,
    contents: &[u8],
    seconds: i64,
) -> git2::Oid {
    git_commit_file_with_offset(repo, relative_path, contents, seconds, 0)
}

pub(crate) fn git_commit_file_with_offset(
    repo: &git2::Repository,
    relative_path: &str,
    contents: &[u8],
    seconds: i64,
    offset_minutes: i32,
) -> git2::Oid {
    let workdir = repo.workdir().expect("test repo has workdir");
    let path = workdir.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("git fixture parent creates");
    }
    fs::write(&path, contents).expect("git fixture file writes");
    let mut index = repo.index().expect("git index opens");
    index
        .add_path(Path::new(relative_path))
        .expect("git fixture path stages");
    index.write().expect("git index writes");
    git_commit_index_with_offset(repo, "fixture commit", seconds, offset_minutes)
}

pub(crate) fn git_repo_with_file(prefix: &str) -> (PathBuf, git2::Oid) {
    let dir = unique_temp_dir(prefix);
    let repo = git2::Repository::init(&dir).expect("git fixture repo initializes");
    let oid = git_commit_file(&repo, "data.txt", b"git-data", 1_700_000_000);
    (dir, oid)
}

pub(crate) fn git_repo_with_tag(prefix: &str) -> (PathBuf, git2::Oid) {
    let (dir, oid) = git_repo_with_file(prefix);
    let repo = git2::Repository::open(&dir).expect("git fixture repo opens");
    let object = repo
        .find_object(oid, Some(git2::ObjectType::Commit))
        .expect("git fixture commit object exists");
    repo.tag_lightweight("v1", &object, false)
        .expect("git fixture tag creates");
    (dir, oid)
}

pub(crate) fn git_repo_with_submodule(prefix: &str) -> (PathBuf, PathBuf, git2::Oid) {
    let sub_dir = unique_temp_dir(&format!("{prefix}-sub"));
    let sub_repo = git2::Repository::init(&sub_dir).expect("git submodule repo initializes");
    git_commit_file(&sub_repo, "sub.txt", b"submodule-data", 1_700_000_000);

    let parent_dir = unique_temp_dir(prefix);
    let parent_repo = git2::Repository::init(&parent_dir).expect("git parent repo initializes");
    fs::write(parent_dir.join("root.txt"), b"root-data").expect("git parent file writes");
    let sub_url = path_source(&sub_dir);
    let mut submodule = parent_repo
        .submodule(&sub_url, Path::new("deps/sub"), true)
        .expect("git submodule adds");
    submodule.clone(None).expect("git submodule clones");
    submodule
        .add_finalize()
        .expect("git submodule add finalizes");
    let mut index = parent_repo.index().expect("git parent index opens");
    index
        .add_path(Path::new("root.txt"))
        .expect("git parent root file stages");
    index.write().expect("git parent index writes");
    drop(index);
    let oid = git_commit_index(&parent_repo, "parent fixture commit", 1_700_000_060);
    (parent_dir, sub_dir, oid)
}

pub(crate) fn append_tar_bytes<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    mode: u32,
    bytes: &[u8],
) {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).expect("tar path is valid");
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    builder
        .append(&header, bytes)
        .expect("tar fixture entry appends");
}

pub(crate) fn fetch_tarball_fixture(prefix: &str) -> (PathBuf, PathBuf) {
    let dir = unique_temp_dir(prefix);
    let archive_path = dir.join("root.tar.gz");
    let file = fs::File::create(&archive_path).expect("tarball fixture creates");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_tar_bytes(&mut builder, "root/file.txt", 0o644, b"data");
    append_tar_bytes(&mut builder, "root/sub/nested.txt", 0o644, b"inner");
    let encoder = builder.into_inner().expect("tar fixture finalizes");
    encoder.finish().expect("gzip fixture finalizes");
    (dir, archive_path)
}

pub(crate) fn gzip_encoded_http_fixture(
    url_path: &str,
    plain_body: &[u8],
) -> (String, String, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("HTTP fixture binds");
    let address = listener
        .local_addr()
        .expect("HTTP fixture address resolves");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, plain_body).expect("HTTP fixture gzip writes");
    let body = encoder.finish().expect("HTTP fixture gzip finalizes");
    let body_hash = format!("{:x}", Sha256::digest(&body));
    let response_header = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("HTTP fixture accepts request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read =
                std::io::Read::read(&mut stream, &mut buffer).expect("HTTP fixture reads request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        std::io::Write::write_all(&mut stream, response_header.as_bytes())
            .expect("HTTP fixture writes response header");
        std::io::Write::write_all(&mut stream, &body).expect("HTTP fixture writes response body");
        request
    });

    (format!("http://{address}{url_path}"), body_hash, handle)
}

pub(crate) fn assert_http_fixture_requested_identity(request: Vec<u8>, operation: &str) {
    let request = String::from_utf8(request).expect("HTTP request is UTF-8");
    assert!(
        request
            .lines()
            .any(|line| line.eq_ignore_ascii_case("accept-encoding: identity")),
        "{operation} HTTP request should ask for raw identity bytes, got: {request:?}"
    );
}

pub(crate) fn path_source(path: &Path) -> String {
    path.to_str().expect("temp path is UTF-8").to_owned()
}

pub(crate) fn nix_string_literal(text: &str) -> String {
    let mut out = String::from("\"");
    for byte in text.bytes() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            byte => out.push(char::from(byte)),
        }
    }
    out.push('"');
    out
}
