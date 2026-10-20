//! Proves downstream crates can supply their own object-safe exposure executor.
#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "Assertions intentionally fail on a poisoned fixture mutex."
)]

use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use terrane_sdk::{
    repository::Error,
    surface::{
        Endpoint, EndpointKind, ExposureState, ExposureStatus, ReaderMode, SchemaState, Serving,
        ServingHandle, Surface, TreeSchema, View,
    },
};

struct ExternalSurface {
    events: Arc<Mutex<Vec<&'static str>>>,
}
struct ExternalExecutor {
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl Surface for ExternalSurface {
    fn schema(&self) -> TreeSchema {
        TreeSchema::default()
    }

    async fn serve(&self, _view: View, _endpoint: Endpoint) -> Result<ServingHandle, Error> {
        self.events.lock().unwrap().push("serve");
        Ok(Box::new(ExternalExecutor {
            events: Arc::clone(&self.events),
        }))
    }
}

impl Serving for ExternalExecutor {
    fn status(&self) -> ExposureStatus {
        let events = self.events.lock().unwrap();
        ExposureStatus {
            commit: [7; 32],
            surface: "x-contract",
            realizer: None,
            features: Vec::new(),
            reader: ReaderMode::Pinned,
            writer: None,
            last_commit: None,
            schema: SchemaState::Valid,
            state: if events.contains(&"stop") {
                ExposureState::Stopped
            } else if events.contains(&"drain") {
                ExposureState::Drained
            } else {
                ExposureState::Serving
            },
        }
    }

    fn drain(&self, _deadline: Duration) -> Result<(), Error> {
        self.events.lock().unwrap().push("drain");
        Ok(())
    }

    fn stop(&self) -> Result<(), Error> {
        self.events.lock().unwrap().push("stop");
        Ok(())
    }
}

fn complete_immediate<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the fixture creates its executor without asynchronous work"),
    }
}

#[test]
fn external_surface_owns_real_lifecycle_without_sdk_constructor_or_registration() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let implementation = ExternalSurface {
        events: Arc::clone(&events),
    };
    let surface: &dyn Surface = &implementation;
    let handle = complete_immediate(surface.serve(
        View::parse("refs/heads/main").unwrap(),
        Endpoint {
            kind: EndpointKind::UnixSocket,
            address: "/unused-contract-endpoint".into(),
        },
    ))
    .unwrap();
    let lifecycle: &dyn Serving = handle.as_ref();
    assert_eq!(lifecycle.status().surface, "x-contract");
    assert_eq!(lifecycle.status().state, ExposureState::Serving);
    lifecycle.drain(Duration::ZERO).unwrap();
    assert_eq!(lifecycle.status().state, ExposureState::Drained);
    lifecycle.stop().unwrap();
    assert_eq!(lifecycle.status().state, ExposureState::Stopped);
    assert_eq!(*events.lock().unwrap(), ["serve", "drain", "stop"]);
    assert!(terrane_sdk::surface::registration("x-contract").is_none());
}
