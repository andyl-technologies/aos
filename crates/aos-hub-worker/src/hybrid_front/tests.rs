//! Real HTTP origin fixtures for cache bypass, overload and cancellation.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::get, Router};
use http::{HeaderMap, Method, Response};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use super::*;

type Reply = Response<Vec<u8>>;
type Cache = Arc<Mutex<BTreeMap<String, (i64, Reply)>>>;

#[derive(Clone)]
struct Origin {
    calls: Arc<AtomicUsize>,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

struct Fixture {
    address: std::net::SocketAddr,
    origin: Origin,
    cache: Cache,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture() -> Fixture {
    let origin = Origin {
        calls: Arc::new(AtomicUsize::new(0)),
        started: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    };
    let app = Router::new()
        .route(
            "/immutable",
            get(|State(origin): State<Origin>| async move {
                origin.calls.fetch_add(1, Ordering::SeqCst);
                (
                    [
                        ("cache-control", "public, max-age=3600, immutable"),
                        ("vary", "Accept-Encoding"),
                    ],
                    "approved-public-metadata",
                )
            }),
        )
        .route(
            "/private",
            get(|State(origin): State<Origin>| async move {
                origin.calls.fetch_add(1, Ordering::SeqCst);
                (
                    [("cache-control", "private, no-store")],
                    "private-origin-response",
                )
            }),
        )
        .route(
            "/held",
            get(|State(origin): State<Origin>| async move {
                origin.calls.fetch_add(1, Ordering::SeqCst);
                origin.started.notify_one();
                origin.release.notified().await;
                "completed-origin-response"
            }),
        )
        .with_state(origin.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        address,
        origin,
        cache: Arc::new(Mutex::new(BTreeMap::new())),
        server,
    }
}

struct HttpFront {
    address: std::net::SocketAddr,
    path: &'static str,
    cache: Cache,
    now: i64,
    cache_unavailable: bool,
}

impl Fixture {
    fn transport(&self, path: &'static str, now: i64) -> HttpFront {
        HttpFront {
            address: self.address,
            path,
            cache: Arc::clone(&self.cache),
            now,
            cache_unavailable: false,
        }
    }
}

#[async_trait::async_trait]
impl FrontTransport for HttpFront {
    type Response = Reply;
    type Error = io::Error;

    async fn cached(&mut self, key: &str) -> io::Result<Option<Reply>> {
        if self.cache_unavailable {
            return Err(io::Error::other("cache read unavailable"));
        }
        Ok(self
            .cache
            .lock()
            .unwrap()
            .get(key)
            .and_then(|(expiry, response)| (*expiry > self.now).then(|| response.clone())))
    }

    async fn origin(&mut self) -> io::Result<Reply> {
        let mut stream = TcpStream::connect(self.address).await?;
        stream
            .write_all(
                format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    self.path, self.address,
                )
                .as_bytes(),
            )
            .await?;
        let mut bytes = Vec::new();
        stream.take(1024 * 1024).read_to_end(&mut bytes).await?;
        let split = bytes
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        let headers = std::str::from_utf8(&bytes[..split]).unwrap();
        let mut lines = headers.lines();
        let status = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let mut response = Response::builder().status(status);
        for line in lines {
            let (name, value) = line.split_once(':').unwrap();
            response = response.header(name, value.trim());
        }
        Ok(response.body(bytes[split + 4..].to_vec()).unwrap())
    }

    async fn store(&mut self, key: &str, response: &mut Reply) -> io::Result<()> {
        if self.cache_unavailable {
            return Err(io::Error::other("cache write unavailable"));
        }
        if let Some(age) = response_age(
            response.status().as_u16(),
            response.headers(),
            response.body().len(),
        ) {
            self.cache
                .lock()
                .unwrap()
                .insert(key.to_owned(), (self.now + age, response.clone()));
        }
        Ok(())
    }

    fn refused(&self, refusal: Refusal) -> io::Result<Reply> {
        Ok(Response::builder()
            .status(if refusal == Refusal::RateLimited {
                429
            } else {
                503
            })
            .body(Vec::new())
            .unwrap())
    }
}

fn key(headers: &HeaderMap) -> Option<String> {
    request_key(
        "deployment",
        "asset-build",
        &Method::GET,
        &url::Url::parse("https://public.invalid/example/-/packages").unwrap(),
        headers,
    )
}

#[test]
fn byte_cache_binds_fresh_grant_source_and_never_shares_private_or_large_bodies() {
    use aos_hub_core::hybrid_ingress::{HybridDeliveryBinding, HybridDeliveryTarget};

    let target = HybridDeliveryTarget {
        object_key: "objects/immutable-metadata".into(),
        external_binding: Some(HybridDeliveryBinding {
            binding_id: 7,
            binding_resource_version: 3,
        }),
        object_size: 32,
        object_etag: "\"original-etag\"".into(),
        content_type: "application/json".into(),
        cache_control: "public, max-age=3600, immutable".into(),
        producer_document: false,
        planned_response: None,
    };
    let url = url::Url::parse("https://public.invalid/registry/object").unwrap();
    let headers = HeaderMap::new();
    assert_eq!(
        origin_class(&Method::GET, &url, &headers),
        OriginClass::Control
    );
    assert_eq!(
        origin_class(
            &Method::GET,
            &url::Url::parse("https://public.invalid/example/-/packages").unwrap(),
            &headers
        ),
        OriginClass::Browse
    );
    let key = delivery_key("deployment", &url, &Method::GET, &headers, &target).unwrap();
    let mut changed = target.clone();
    changed.object_etag = "\"replacement-etag\"".into();
    assert_ne!(
        delivery_key("deployment", &url, &Method::GET, &headers, &changed),
        Some(key.clone())
    );
    changed = target.clone();
    changed
        .external_binding
        .as_mut()
        .unwrap()
        .binding_resource_version += 1;
    assert_ne!(
        delivery_key("deployment", &url, &Method::GET, &headers, &changed),
        Some(key)
    );
    changed = target.clone();
    changed.cache_control = "private, no-store".into();
    assert!(delivery_key("deployment", &url, &Method::GET, &headers, &changed).is_none());
    changed = target.clone();
    changed.object_size = policy::MAX_CACHE_BODY_BYTES as u64 + 1;
    assert!(delivery_key("deployment", &url, &Method::GET, &headers, &changed).is_none());
    let mut headers = headers;
    headers.insert("authorization", "Bearer private".parse().unwrap());
    assert!(delivery_key("deployment", &url, &Method::GET, &headers, &target).is_none());
}

#[tokio::test]
async fn public_immutable_http_hit_skips_origin_and_expiry_rechecks_it() {
    let fixture = fixture().await;
    let shield = OriginShield::new(ShieldLimits::default());
    let key = key(&HeaderMap::new()).unwrap();
    for now in [100, 101] {
        let response = dispatch(
            &mut fixture.transport("/immutable", now),
            &shield,
            OriginClass::Browse,
            "client",
            Some(&key),
            now,
        )
        .await
        .unwrap();
        assert_eq!(response.body(), b"approved-public-metadata");
    }
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 1);

    dispatch(
        &mut fixture.transport("/immutable", 160),
        &shield,
        OriginClass::Browse,
        "client",
        Some(&key),
        160,
    )
    .await
    .unwrap();
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 2);

    let mut transport = fixture.transport("/immutable", 161);
    transport.cache_unavailable = true;
    let response = dispatch(
        &mut transport,
        &shield,
        OriginClass::Browse,
        "client",
        Some(&key),
        161,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn private_http_responses_and_personalized_requests_never_share_entries() {
    let fixture = fixture().await;
    let shield = OriginShield::new(ShieldLimits::default());
    let key = key(&HeaderMap::new()).unwrap();
    for _ in 0..2 {
        dispatch(
            &mut fixture.transport("/private", 100),
            &shield,
            OriginClass::Browse,
            "client",
            Some(&key),
            100,
        )
        .await
        .unwrap();
    }
    assert!(fixture.cache.lock().unwrap().is_empty());
    dispatch(
        &mut fixture.transport("/immutable", 100),
        &shield,
        OriginClass::Browse,
        "client",
        Some(&key),
        100,
    )
    .await
    .unwrap();
    for (name, value) in [
        ("authorization", "Bearer private"),
        ("cookie", "theme=dark"),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        assert!(self::key(&headers).is_none());
        dispatch(
            &mut fixture.transport("/immutable", 101),
            &shield,
            OriginClass::Browse,
            "client",
            None,
            101,
        )
        .await
        .unwrap();
    }
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 5);

    let mut headers = HeaderMap::new();
    headers.insert("accept-encoding", "gzip".parse().unwrap());
    assert_ne!(self::key(&headers), Some(key));
    for value in [
        "private, immutable, max-age=60",
        "public, no-store, immutable, max-age=60",
        "public, max-age=60",
    ] {
        headers.insert("cache-control", value.parse().unwrap());
        assert!(response_age(200, &headers, 32).is_none());
    }
    headers.insert(
        "cache-control",
        "public, immutable, max-age=60".parse().unwrap(),
    );
    headers.insert("set-cookie", "session=secret".parse().unwrap());
    assert!(response_age(200, &headers, 32).is_none());
    headers.remove("set-cookie");
    headers.insert("vary", "Authorization".parse().unwrap());
    assert!(response_age(200, &headers, 32).is_none());
    headers.remove("vary");
    headers.insert(
        "cache-control",
        "public, immutable, max-age=60, s-maxage=10"
            .parse()
            .unwrap(),
    );
    headers.insert("age", "9".parse().unwrap());
    assert_eq!(response_age(200, &headers, 32), Some(1));
    headers.insert("age", "10".parse().unwrap());
    assert!(response_age(200, &headers, 32).is_none());
}

#[tokio::test]
async fn held_http_origin_refuses_overload_and_cancellation_releases_admission() {
    let fixture = fixture().await;
    let shield = OriginShield::new(ShieldLimits {
        active: 1,
        ..Default::default()
    });
    let mut held_transport = fixture.transport("/held", 100);
    let held_shield = shield.clone();
    let task = tokio::spawn(async move {
        dispatch(
            &mut held_transport,
            &held_shield,
            OriginClass::Browse,
            "client",
            None,
            100,
        )
        .await
    });
    fixture.origin.started.notified().await;
    let overloaded = dispatch(
        &mut fixture.transport("/immutable", 100),
        &shield,
        OriginClass::Browse,
        "other",
        None,
        100,
    )
    .await
    .unwrap();
    assert_eq!(overloaded.status(), 503);
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 1);

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let recovered = dispatch(
        &mut fixture.transport("/immutable", 101),
        &shield,
        OriginClass::Browse,
        "client",
        None,
        101,
    )
    .await
    .unwrap();
    assert_eq!(recovered.status(), 200);
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 2);
    fixture.origin.release.notify_one();
}

#[tokio::test]
async fn local_rate_limits_do_not_dispatch_and_recover_only_after_window() {
    let fixture = fixture().await;
    let shield = OriginShield::new(ShieldLimits {
        browse_per_minute: 1,
        clients: 1,
        ..Default::default()
    });
    dispatch(
        &mut fixture.transport("/private", 100),
        &shield,
        OriginClass::Browse,
        "client",
        None,
        100,
    )
    .await
    .unwrap();
    for (client, now) in [("client", 101), ("client", 99), ("new-client", 101)] {
        let refused = dispatch(
            &mut fixture.transport("/private", now),
            &shield,
            OriginClass::Browse,
            client,
            None,
            now,
        )
        .await
        .unwrap();
        assert_eq!(refused.status(), 429);
    }
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 1);
    let recovered = dispatch(
        &mut fixture.transport("/private", 120),
        &shield,
        OriginClass::Browse,
        "client",
        None,
        120,
    )
    .await
    .unwrap();
    assert_eq!(recovered.status(), 200);
    assert_eq!(fixture.origin.calls.load(Ordering::SeqCst), 2);
}
