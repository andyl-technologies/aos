//! Machine-surface path and response-metadata classification.
//!
//! Producers and servers share this module so publication admission, upload
//! ordering, consistency planning, and HTTP responses use one path contract.

/// The machine-surface directory prefixes (also valid as bare paths).
const MACHINE_DIRS: [&str; 8] = [
    "info",
    "objects",
    "channels",
    "releases",
    "publication-receipts",
    "nar",
    "web",
    "browse",
];

/// Cache-control for content-addressed payloads.
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// Cache-control for pointers and replaceable metadata.
pub const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// Reports whether a relative path belongs to the machine surface.
#[must_use]
pub fn is_machine_path(path: &str) -> bool {
    path == "HEAD"
        || path == "nix-cache-info"
        || path == "index.html"
        || path.ends_with(".narinfo")
        || is_image_object_path(path)
        || MACHINE_DIRS
            .iter()
            .any(|dir| path == *dir || path.starts_with(&format!("{dir}/")))
}

/// Returns the cache-control policy for a machine path.
#[must_use]
pub fn cache_control(path: &str) -> &'static str {
    let immutable = if let Some(rest) = path.strip_prefix("objects/") {
        !rest.starts_with("info/")
    } else if let Some(rest) = path.strip_prefix("web/") {
        rest != "config.json" && rest != "index.json" && !rest.starts_with("packages/")
    } else {
        (path.starts_with("releases/") && !is_release_object_info_path(path))
            || path.starts_with("publication-receipts/")
            || path.starts_with("nar/")
            || is_image_object_path(path)
    };
    if immutable {
        IMMUTABLE_CACHE_CONTROL
    } else {
        MUTABLE_CACHE_CONTROL
    }
}

/// Returns the HTTP media type for a machine path.
#[must_use]
pub fn content_type(path: &str) -> &'static str {
    if path.ends_with(".narinfo") {
        "text/x-nix-narinfo"
    } else if path.starts_with("images/") && path.ends_with(".img.zst") {
        "application/vnd.aos.disk-image.raw+zstd"
    } else if path.ends_with(".nar.zst") || path.ends_with(".zst") {
        "application/zstd"
    } else if path.ends_with(".nar.xz") || path.ends_with(".xz") {
        "application/x-xz"
    } else if path.starts_with("images/") && path.ends_with("image-info.json") {
        "application/vnd.aos.image-info+json"
    } else if path.starts_with("images/") && path.ends_with(".qcow2") {
        "application/vnd.aos.disk-image.qcow2"
    } else if path.starts_with("images/") && path.ends_with(".vmdk") {
        "application/x-vmdk"
    } else if path.starts_with("images/") && path.ends_with(".vhd") {
        "application/vnd.aos.disk-image.vhd"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".js") {
        "text/javascript"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path == "HEAD"
        || path == "nix-cache-info"
        || path.starts_with("info/")
        || is_release_object_info_path(path)
    {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn is_release_object_info_path(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    matches!(parts.as_slice(), ["releases", _, _, _, "objects", "info", ..])
}

fn is_image_object_path(path: &str) -> bool {
    image_object_sha256(path).is_some()
}

/// Returns the content digest encoded by a canonical immutable image path.
#[must_use]
pub fn image_object_sha256(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("images/sha256/")?;
    let parts = rest.split('/').collect::<Vec<_>>();
    let digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let filename = |value: &str| {
        !value.is_empty()
            && value.is_ascii()
            && !value.starts_with('.')
            && !value.contains("..")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    match parts.as_slice() {
        [sha256, name] if digest(sha256) && filename(name) => Some(*sha256),
        [disk_sha256, "metadata", info_sha256, "image-info.json"] => {
            (digest(disk_sha256) && digest(info_sha256)).then_some(*info_sha256)
        }
        _ => None,
    }
}

/// Reports whether a machine path contains producer-controlled executable content.
#[must_use]
pub fn is_producer_document(path: &str) -> bool {
    path.ends_with(".html") || path.ends_with(".js")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutable_and_immutable_paths_share_one_contract() {
        for path in [
            "HEAD",
            "info/refs",
            "objects/info/packs",
            "channels/stable/00",
            "nix-cache-info",
            "abcd.narinfo",
            "web/config.json",
            "web/index.json",
            "web/packages/aos.json",
            "releases/1/0/0/objects/info/packs",
        ] {
            assert!(is_machine_path(path), "{path}");
            assert_eq!(cache_control(path), MUTABLE_CACHE_CONTROL, "{path}");
        }
        for path in [
            "objects/ab/cd",
            "releases/aos.json",
            "releases/1/0/0/objects/pack/pack-demo.pack",
            "nar/aos.nar.zst",
            "images/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aos.qcow2",
        ] {
            assert!(is_machine_path(path), "{path}");
            assert_eq!(cache_control(path), IMMUTABLE_CACHE_CONTROL, "{path}");
        }
    }
}
