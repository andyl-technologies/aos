//! Immediate request-signal cleanup for one native copy invocation.
//!
//! A canceled I/O context need not poll its Rust future again. The signal
//! callback therefore closes native resources and releases its capacity permit
//! directly. It neither acknowledges nor removes a permanent physical turn.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use anyhow::{ensure, Result};
use js_sys::{Function, Reflect};
use wasm_bindgen::{closure::Closure, JsCast as _, JsValue};

use crate::direct_upload::provider_capacity::Permit;

#[cfg(feature = "do-e2e")]
thread_local! {
    static SIGNAL_CLOSES: Cell<u64> = const { Cell::new(0) };
}

#[cfg(feature = "do-e2e")]
/// Counts actual native request-signal callbacks in the controlled artifact.
pub(super) fn signal_closes() -> u64 {
    SIGNAL_CLOSES.with(Cell::get)
}

pub(super) struct Lifetime {
    signal: worker::web_sys::AbortSignal,
    callback: Closure<dyn FnMut(JsValue)>,
    resources: Rc<Resources>,
}

#[derive(Default)]
struct Resources {
    closed: Cell<bool>,
    capacity: RefCell<Option<Permit>>,
    native: RefCell<Vec<(JsValue, &'static str)>>,
}

pub(super) struct Registration {
    resources: Rc<Resources>,
    object: JsValue,
}

impl Lifetime {
    /// Retains a signal listener until this invocation's owner is dropped.
    ///
    /// # Errors
    /// Refuses an unavailable listener API or an already canceled request.
    pub(super) fn new(signal: worker::web_sys::AbortSignal) -> Result<Self> {
        let resources = Rc::new(Resources::default());
        let observed = Rc::clone(&resources);
        let callback = Closure::new(move |_| {
            #[cfg(feature = "do-e2e")]
            SIGNAL_CLOSES.with(|count| count.set(count.get().saturating_add(1)));
            observed.close();
        });
        event_listener(&signal, "addEventListener", &callback)?;
        let owner = Self {
            signal,
            callback,
            resources,
        };
        if owner.signal.aborted() {
            owner.resources.close();
        }
        owner.check()?;
        Ok(owner)
    }

    /// Refuses dispatch after immediate cancellation cleanup.
    ///
    /// # Errors
    /// Returns an error once the request's native signal has closed the owner.
    pub(super) fn check(&self) -> Result<()> {
        ensure!(!self.resources.closed.get(), "copy invocation closed");
        Ok(())
    }

    /// Takes the invocation's already acquired provider pool permit.
    ///
    /// # Errors
    /// Refuses a closed owner or repeated capacity attachment.
    pub(super) fn retain_capacity(&self, permit: Permit) -> Result<()> {
        self.check()?;
        ensure!(
            self.resources.capacity.borrow().is_none(),
            "copy capacity already retained"
        );
        *self.resources.capacity.borrow_mut() = Some(permit);
        Ok(())
    }

    /// Registers one native abort/cancel operation beside its ordinary Rust owner.
    ///
    /// # Errors
    /// Refuses canceled invocation, excessive resources or absent native method.
    pub(super) fn register(&self, object: JsValue, method: &'static str) -> Result<Registration> {
        self.check()?;
        function(&object, method)?;
        ensure!(
            self.resources.native.borrow().len() < 4,
            "copy native resource bound exceeded"
        );
        self.resources
            .native
            .borrow_mut()
            .push((object.clone(), method));
        Ok(Registration {
            resources: Rc::clone(&self.resources),
            object,
        })
    }
}

impl Drop for Lifetime {
    fn drop(&mut self) {
        let _ = event_listener(&self.signal, "removeEventListener", &self.callback);
        self.resources.close();
    }
}

impl Resources {
    fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        // Remove the collection before invoking native methods so callbacks
        // cannot borrow a live mutable list or retain another dispatch owner.
        for (object, method) in self.native.take() {
            if let Ok(cleanup) = function(&object, method) {
                if let Ok(result) = cleanup.call0(&object) {
                    if let Ok(catch) = function(&result, "catch") {
                        if let Ok(handler) = Reflect::get(&js_sys::global(), &"Boolean".into()) {
                            let _ = catch.call1(&result, &handler);
                        }
                    }
                }
            }
        }
        self.capacity.borrow_mut().take();
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.resources
            .native
            .borrow_mut()
            .retain(|(object, _)| object != &self.object);
    }
}

fn function(object: &JsValue, name: &str) -> Result<Function> {
    Reflect::get(object, &name.into())
        .map_err(|_| anyhow::anyhow!("copy native cleanup unavailable"))?
        .dyn_into::<Function>()
        .map_err(|_| anyhow::anyhow!("copy native cleanup unavailable"))
}

fn event_listener(
    signal: &worker::web_sys::AbortSignal,
    method: &str,
    callback: &Closure<dyn FnMut(JsValue)>,
) -> Result<()> {
    function(signal.as_ref(), method)?
        .call2(signal.as_ref(), &"abort".into(), callback.as_ref())
        .map_err(|_| anyhow::anyhow!("copy request listener unavailable"))?;
    Ok(())
}
